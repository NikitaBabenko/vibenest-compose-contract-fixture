# Pinned 4.7.5 request audit

Inspected coollabsio/coolify commit378ce3735c4522ebb6b68e93b909b0511f278763,
app/Http/Controllers/Api/ApplicationsController.php. Source inspection is not a
claim that the remaining runtime checkpoints have passed.

| Fixture mutation | Source contract | Result |
|---|---|---|
| POST applications/public | create_public_application585 delegates create path; allowedFields1613, validation1633; settings1697 onward | All body keys are allowed: name, project_uuid, environment_name, server_uuid, git_repository, git_branch, git_commit_sha, build_pack, ports_exposes, docker_compose_location/domains/custom commands, is_preserve_repository_enabled, is_auto_deploy_enabled, is_preview_deployments_enabled, instant_deploy. Both preceding attempts created this resource. |
| POST applications/uuid/envs | create_env4653; allowedFields4655, validator4675, unknown fields4687, runtime/build defaults4750 onward | is_buildtime=false is the correct spelling; is_runtime defaults true. is_build_time is rejected422. All other actual keys allowed. |
| PATCH applications/uuid | update_by_uuid3629; allowlist3662, extraFields3759, request-only fill4071 | The only keys sent are docker_compose_custom_build_command and docker_compose_custom_start_command, both allowed strings. true is a shell command string, not a JSON boolean. No source/host/volume mutation is hidden in PATCH. |
| POST applications/uuid/start | action_deploy4942; queue4963, response4993 | No JSON payload. Expects deployment_uuid; skipped/unknown response stops fixture without retry. |
| POST applications/uuid/restart | action_restart5142; queue5160, response5187 | No JSON payload. Same receipt requirement; Compose disables restart_only in the job, so exact retained resume remains a custom-command requirement. |
| POST applications/uuid/stop | action_stop5056; boolean docker_cleanup5073; dispatch5074 | JSON boolean false is read by Request::boolean, no additional allowlist; preserves native stop/remove but suppresses cleanup. Default StopApplication removeContainers=true. Fixture still requires actual runtime=[] before proceeding. |

POST projects sends only name, unchanged and already accepted in both attempts.
All other calls are GET version/servers/application/deployment. No retries or
automatic mutation compensation are introduced. Local schema assertion checks
the actual ENV call AST against the pinned provider's allowed fields.
