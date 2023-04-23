import os

import jinja2
from opal_common.logger import logger

from horizon.config import SidecarConfig


def get_jinja_environment() -> jinja2.Environment:
    path = os.path.join(os.path.dirname(__file__), "../../static/templates")
    return jinja2.Environment(loader=jinja2.FileSystemLoader(path))


def persist_to_file(contents: str, path: str) -> str:
    path = os.path.expanduser(path)

    # make sure the directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # persist to file
    with open(path, "w") as f:
        f.write(contents)

    return path


def get_opa_config_file_path(
    sidecar_config: SidecarConfig,
    template_path="config.yaml.template",
) -> str:
    """
    renders a template that implements the OPA config file, according to the official spec:
    https://www.openpolicyagent.org/docs/latest/configuration/

    puts the rendered contents in a file and returns the path to that file.

    NOTE: Not all features of the config are implemented - only decision logs for now.
    """
    env = get_jinja_environment()
    target_path = sidecar_config.OPA_CONFIG_FILE_PATH
    decision_logs_backend_tier = (
        sidecar_config.OPA_DECISION_LOG_INGRESS_BACKEND_TIER_URL
        or sidecar_config.CONTROL_PLANE
    )
    logger.info(
        "Uploading decision logs to backend tier: {tier}",
        tier=decision_logs_backend_tier,
    )

    try:
        template = env.get_template(template_path)
        contents = template.render(
            cloud_service_url=decision_logs_backend_tier,
            bearer_token=sidecar_config.API_KEY,
            log_ingress_endpoint=sidecar_config.OPA_DECISION_LOG_INGRESS_ROUTE,
            min_delay_seconds=sidecar_config.OPA_DECISION_LOG_MIN_DELAY,
            max_delay_seconds=sidecar_config.OPA_DECISION_LOG_MAX_DELAY,
            upload_size_limit_bytes=sidecar_config.OPA_DECISION_LOG_UPLOAD_SIZE_LIMIT,
            log_to_console=sidecar_config.OPA_DECISION_LOG_CONSOLE,
        )
    except jinja2.TemplateNotFound:
        logger.error(f"could not find the template: {template_path}")
        raise
    except jinja2.TemplateError:
        logger.error(f"could not render the template: {template_path}")
        raise

    return persist_to_file(contents, target_path)


def get_opa_authz_policy_file_path(
    sidecar_config: SidecarConfig,
    template_path="authz.rego.template",
) -> str:
    """
    renders a template that implements a rego policy for OPA authz, as demonstrated here:
    https://www.openpolicyagent.org/docs/latest/security/#token-based-authentication-example

    puts the rendered contents in a file and returns the path to that file.
    """
    env = get_jinja_environment()
    target_path = sidecar_config.OPA_AUTH_POLICY_FILE_PATH

    try:
        template = env.get_template(template_path)
        contents = template.render(bearer_token=sidecar_config.API_KEY)
    except jinja2.TemplateNotFound:
        logger.error(f"could not find the template: {template_path}")
        raise
    except jinja2.TemplateError:
        logger.error(f"could not render the template: {template_path}")
        raise

    return persist_to_file(contents, target_path)
