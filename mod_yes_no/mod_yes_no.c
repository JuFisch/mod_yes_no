/**
 * Module to check if a prefork process should exit based on the response of a
 * yes-no daemon.
 *
 * TODO
 * - set a custom header, and read the header name from config
 * - we open and close the socket every request. yuck. fix the yes-no daemon
 *   to not do that.
 * - enforce that this is the prefork-mpm, or make this thread safe
 */

#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"

typedef struct {
  /* Path to unix socket. */
  char socket_path[512];
  /* Amount of memory in MB to ask the yes-no daemon for. */
  int desired_memory;
  /* Name of custom header to send when the yes-no daemon says no. */
  char header_503_name[512];
} yes_no_config;

static void yes_no_register_hooks(apr_pool_t *pool);
static int yes_no_handler(request_rec *r);
static int yes_no_handle_request(yes_no_config *config);
static int yes_no_create_socket(yes_no_config *config);
static const char *yes_no_set_socket_path(cmd_parms *cmd, void *cfg, const char *arg);
static const char *yes_no_set_desired_memory(cmd_parms *cmd, void *cfg, const char *arg);
static const char *yes_no_set_header_503_name(cmd_parms *cmd, void *cfg, const char *arg);
static void *yes_no_create_server_config(apr_pool_t *pool, server_rec *s);

int yes_no_socket_fd;

static const command_rec yes_no_directives[] =
{
  AP_INIT_TAKE1("YesNoSocketPath", yes_no_set_socket_path, NULL, RSRC_CONF, "The path to the yes-no daemon socket."),
  AP_INIT_TAKE1("YesNoDesiredMemory", yes_no_set_desired_memory, NULL, RSRC_CONF, "The amount of memory we want to service a request."),
  AP_INIT_TAKE1("YesNoHeader503Name", yes_no_set_header_503_name, NULL, RSRC_CONF, "The name of the header to send with a 503 response."),
  { NULL }
};

module AP_MODULE_DECLARE_DATA yes_no_module =
{
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  yes_no_create_server_config,
  NULL,
  yes_no_directives,
  yes_no_register_hooks
};

static void yes_no_register_hooks(apr_pool_t *pool)
{
  ap_hook_handler(yes_no_handler, NULL, NULL, APR_HOOK_FIRST);
}

static void *yes_no_create_server_config(apr_pool_t *pool, server_rec *s)
{
  yes_no_config *config = apr_pcalloc(pool, sizeof(yes_no_config));

  config->desired_memory = 0;
  memset(config->header_503_name, 0, 512);
  memset(config->socket_path, 0, 512);

  return config;
}

static const char *yes_no_set_socket_path(cmd_parms *cmd, void *cfg, const char *arg)
{
  yes_no_config *conf;
  conf = ap_get_module_config(cmd->server->module_config, &yes_no_module);

  // TODO: prolly check arg, and use some apr_pool stuff.
  strcpy(conf->socket_path, arg);

  return NULL;
}

static const char *yes_no_set_desired_memory(cmd_parms *cmd, void *cfg, const char *arg)
{
  yes_no_config *conf;
  conf = ap_get_module_config(cmd->server->module_config, &yes_no_module);

  // TODO: prolly check arg eh why not eh YOLO
  conf->desired_memory = apr_strtoi64(arg, NULL, 0);

  return NULL;
}

static const char *yes_no_set_header_503_name(cmd_parms *cmd, void *cfg, const char *arg)
{
  yes_no_config *conf;
  conf = ap_get_module_config(cmd->server->module_config, &yes_no_module);

  // TODO: prolly check arg, and use some apr_pool stuff.
  strcpy(conf->header_503_name, arg);

  return NULL;
}

static int yes_no_create_socket(yes_no_config *config)
{
  struct sockaddr_un saddr;

  yes_no_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (yes_no_socket_fd < 0) {
    syslog(LOG_WARNING, "mod_yes_no[%d]: cannot open control socket: %s", getpid(), strerror(errno));
    return 0;
  }
  memset(&saddr, sizeof(saddr), 0);
  saddr.sun_family = AF_UNIX;
  strcpy(saddr.sun_path, config->socket_path);
  if (connect(yes_no_socket_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
    syslog(LOG_WARNING, "mod_yes_no[%d]: cannot connect to control socket: %s", getpid(), strerror(errno));
    close(yes_no_socket_fd);
    return 0;
  }
  return yes_no_socket_fd;
}

static int yes_no_handle_request(yes_no_config *config)
{
  char version, reply;
  uint64_t request;
  int ret = 1;

  // conf->desired_memory is in MB, yes-no wants bytes.
  request = config->desired_memory * 1024l *1024l;
  version = 1;
  if (write(yes_no_socket_fd, &version, 1) != 1 || write(yes_no_socket_fd, &request, sizeof(request)) != sizeof(request)) {
    syslog(LOG_WARNING, "mod_yes_no[%d]: cannot write to control socket: %s", getpid(), strerror(errno));
    return 1;
  }

  if (read(yes_no_socket_fd, &reply, 1) != 1) {
    syslog(LOG_WARNING, "mod_yes_no[%d]: cannot read control socket: %s", getpid(), strerror(errno));
    return 1;
  }

  if (reply == '1') {
    return 1;
  }
  else if (reply == '0') {
    return 0;
  }
  else {
    syslog(LOG_WARNING, "mod_yes_no[%d]: Unknown reply from control socket.", getpid());
    return 1;
  }
}

static int yes_no_handler(request_rec *r)
{
  int ret = DECLINED;
  yes_no_socket_fd = 0;
  yes_no_config *config = (yes_no_config *) ap_get_module_config(r->server->module_config, &yes_no_module);

  if (!yes_no_create_socket(config)) {
    syslog(LOG_NOTICE, "mod_yes_no[%d]: yes_no_handler, couldn't create yes_no_socket, failing open.", getpid());
  }
  else if (!yes_no_handle_request(config)) {
    syslog(LOG_NOTICE, "mod_yes_no[%d]: yes_no_handler, not enough resources for request.", getpid());
    ret = HTTP_SERVICE_UNAVAILABLE;
  }

  close(yes_no_socket_fd);
  return ret;
}

