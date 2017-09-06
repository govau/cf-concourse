# Server

Befor running, generate a UAA client:

```bash
ENV_DOMAIN=example.com

UAA_CLIENT_SECRET=$(openssl rand -hex 32)
CONCOURSE_CLIENT_SECRET=$(openssl rand -hex 32)

# Need openid for username, and cloud_controller.read for organizations
# Keep this callback as localhost - we don't actually follow it.
uaac client add cf-concourse-integration \
    --name "cf-concourse-integration" \
    --scope "openid cloud_controller.read" \
    --authorized_grant_types "authorization_code" \
    --redirect_uri "https://localhost/oauth2callback" \
    --access_token_validity "3600" \
    --secret "notasecret" \
    --autoapprove true

# Need openid for username, and cloud_controller.read for organizations
# Set this callback to the URL this server will be at, which should be:
# https://cf.system.${ENV_DOMAIN}
uaac client add cf-concourse-web-integration \
    --name "cf-concourse-web-integration" \
    --scope "openid cloud_controller.read" \
    --authorized_grant_types "authorization_code" \
    --redirect_uri "https://concourse.${ENV_DOMAIN}/auth/uaa/callback" \
    --access_token_validity "3600" \
    --secret $WEB_SECRET
```

Build and push it to CloudFoundry:

```bash
govendor sync

cf target -o system -s concourse
cf push
cf set-env cf OUR_URL https://cf.system.${ENV_DOMAIN}
cf set-env cf CONCOURSE_CALLBACK_URL https://concourse.${ENV_DOMAIN}/auth/external/callbac
cf set-env cf CONCOURSE_CLIENT_ID concourse
cf set-env cf CONCOURSE_CLIENT_SECRET $CONCOURSE_CLIENT_SECRET
cf set-env cf UAA_WEB_CLIENT_SECRET $UAA_CLIENT_SECRET
cf set-env cf UAA_WEB_CLIENT_SECRET $UAA_CLIENT_SECRET
cf set-env cf CF_API https://api.system.${ENV_DOMAIN}
cf restage cf
```
