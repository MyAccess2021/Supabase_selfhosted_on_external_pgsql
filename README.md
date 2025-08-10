### Supabase selfhosted using external postgresql instance
# it is .env file 
```bash
############
# Secrets
# YOU MUST CHANGE THESE BEFORE GOING INTO PRODUCTION
############

POSTGRES_PASSWORD=myaccess
JWT_SECRET=bTwgvFJCgpLTsTOOz5okyGznGy9D3gL4JJMWvZr2
ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzU0NTA1MDAwLCJleHAiOjE5MTIyNzE0MDB9.6HTfSydVWzkzSyPBHXL8Z9umdDO667Q7oQdXN2JwYiQ
SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NTQ1MDUwMDAsImV4cCI6MTkxMjI3MTQwMH0.aXWxyL-Xpv-QUd7AKXBSH3vua7QOh4tEXrChw2kj8J0
DASHBOARD_USERNAME=supabase
DASHBOARD_PASSWORD=myaccess
SECRET_KEY_BASE=UpNVntn3cDxHJpq99YMc1T1AQgQpc8kfYTuRgBiYa15BLrx8etQoXz3gZv1/u2oq
VAULT_ENC_KEY=your-encryption-key-32-chars-min


############
# Database - You can change these to any PostgreSQL database that has logical replication enabled.
############

POSTGRES_HOST=96.8.121.100
POSTGRES_USER=supabase_admin
POSTGRES_DB=supabase
POSTGRES_PORT=5432
# default user is postgres


############
# Supavisor -- Database pooler
############
# Port Supavisor listens on for transaction pooling connections
POOLER_PROXY_PORT_TRANSACTION=6543
# Maximum number of PostgreSQL connections Supavisor opens per pool
POOLER_DEFAULT_POOL_SIZE=20
# Maximum number of client connections Supavisor accepts per pool
POOLER_MAX_CLIENT_CONN=100
# Unique tenant identifier
POOLER_TENANT_ID=your-tenant-id
# Pool size for internal metadata storage used by Supavisor
# This is separate from client connections and used only by Supavisor itself
POOLER_DB_POOL_SIZE=5


############
# API Proxy - Configuration for the Kong Reverse proxy.
############

KONG_HTTP_PORT=8000
KONG_HTTPS_PORT=8443
KONG_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzU0NTA1MDAwLCJleHAiOjE5MTIyNzE0MDB9.6HTfSydVWzkzSyPBHXL8Z9umdDO667Q7oQdXN2JwYiQ
KONG_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NTQ1MDUwMDAsImV4cCI6MTkxMjI3MTQwMH0.aXWxyL-Xpv-QUd7AKXBSH3vua7QOh4tEXrChw2kj8J0
SUPABASE_URL=http://kong:8000
############
# API - Configuration for PostgREST.
############

PGRST_DB_SCHEMAS=public,storage,graphql_public


############
# Auth - Configuration for the GoTrue authentication server.
############

## General
SITE_URL=http://192.168.68.241:3000
ADDITIONAL_REDIRECT_URLS=
JWT_EXPIRY=3600
DISABLE_SIGNUP=false
API_EXTERNAL_URL=http://192.168.68.241:8000

## Mailer Config
MAILER_URLPATHS_CONFIRMATION="/auth/v1/verify"
MAILER_URLPATHS_INVITE="/auth/v1/verify"
MAILER_URLPATHS_RECOVERY="/auth/v1/verify"
MAILER_URLPATHS_EMAIL_CHANGE="/auth/v1/verify"

## Email auth
ENABLE_EMAIL_SIGNUP=true
ENABLE_EMAIL_AUTOCONFIRM=false
SMTP_ADMIN_EMAIL=admin@example.com
SMTP_HOST=supabase-mail
SMTP_PORT=2500
SMTP_USER=fake_mail_user
SMTP_PASS=fake_mail_password
SMTP_SENDER_NAME=fake_sender
ENABLE_ANONYMOUS_USERS=false

## Phone auth
ENABLE_PHONE_SIGNUP=true
ENABLE_PHONE_AUTOCONFIRM=true


############
# Studio - Configuration for the Dashboard
############

STUDIO_DEFAULT_ORGANIZATION=Default Organization
STUDIO_DEFAULT_PROJECT=Default Project

STUDIO_PORT=3000
# replace if you intend to use Studio outside of localhost
SUPABASE_PUBLIC_URL=http://192.168.68.241:8000
PUBLIC_REST_URL=http://192.168.68.241:8000/rest/v1
# Enable webp support
IMGPROXY_ENABLE_WEBP_DETECTION=true

# Add your OpenAI API key to enable SQL Editor Assistant
OPENAI_API_KEY=


############
# Functions - Configuration for Functions
############
# NOTE: VERIFY_JWT applies to all functions. Per-function VERIFY_JWT is not supported yet.
FUNCTIONS_VERIFY_JWT=false


############
# Logs - Configuration for Analytics
# Please refer to https://supabase.com/docs/reference/self-hosting-analytics/introduction
############

# Change vector.toml sinks to reflect this change
# these cannot be the same value
LOGFLARE_PUBLIC_ACCESS_TOKEN=your-super-secret-and-long-logflare-key-public
LOGFLARE_PRIVATE_ACCESS_TOKEN=your-super-secret-and-long-logflare-key-private

# Docker socket location - this value will differ depending on your OS
DOCKER_SOCKET_LOCATION=/var/run/docker.sock

# Google Cloud Project details
GOOGLE_PROJECT_ID=GOOGLE_PROJECT_ID
GOOGLE_PROJECT_NUMBER=GOOGLE_PROJECT_NUMBER
```
# It is the docker-compose.yml file
```bash
services:
  studio:
    container_name: supabase-studio
    image: supabase/studio:2025.06.30-sha-6f5982d
    ports:
     - "3000:3000"
    restart: unless-stopped
    environment:
      STUDIO_PG_META_URL: http://meta:8080
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      DEFAULT_ORGANIZATION_NAME: ${STUDIO_DEFAULT_ORGANIZATION}
      DEFAULT_PROJECT_NAME: ${STUDIO_DEFAULT_PROJECT}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
      SUPABASE_URL: http://kong:8000
      SUPABASE_PUBLIC_URL: ${SUPABASE_PUBLIC_URL}
      SUPABASE_ANON_KEY: ${ANON_KEY}
      SUPABASE_SERVICE_KEY: ${SERVICE_ROLE_KEY}
      AUTH_JWT_SECRET: ${JWT_SECRET}
      LOGFLARE_PRIVATE_ACCESS_TOKEN: ${LOGFLARE_PRIVATE_ACCESS_TOKEN}
      LOGFLARE_URL: http://analytics:4000
      NEXT_PUBLIC_ENABLE_LOGS: "true"
      NEXT_ANALYTICS_BACKEND_PROVIDER: postgres

  kong:
    container_name: supabase-kong
    image: kong:2.8.1
    restart: unless-stopped
    ports:
      - ${KONG_HTTP_PORT}:8000
      - ${KONG_HTTPS_PORT}:8443
    volumes:
      - ./volumes/api/kong.yml:/home/kong/temp.yml:ro,z
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /home/kong/kong.yml
      KONG_DNS_ORDER: LAST,A,CNAME
      KONG_PLUGINS: request-transformer,cors,key-auth,acl,basic-auth
      KONG_NGINX_PROXY_PROXY_BUFFER_SIZE: 160k
      KONG_NGINX_PROXY_PROXY_BUFFERS: 64 160k
      SUPABASE_ANON_KEY: ${ANON_KEY}
      SUPABASE_SERVICE_KEY: ${SERVICE_ROLE_KEY}
      DASHBOARD_USERNAME: ${DASHBOARD_USERNAME}
      DASHBOARD_PASSWORD: ${DASHBOARD_PASSWORD}
    entrypoint: bash -c 'eval "echo \"$$(cat ~/temp.yml)\"" > ~/kong.yml && /docker-entrypoint.sh kong docker-start'

  auth:
    container_name: supabase-auth
    image: supabase/gotrue:v2.177.0
    restart: unless-stopped
    environment:
      GOTRUE_API_HOST: 0.0.0.0
      GOTRUE_API_PORT: 9999
      API_EXTERNAL_URL: ${API_EXTERNAL_URL}
      GOTRUE_DB_DRIVER: postgres
      GOTRUE_DB_DATABASE_URL: postgres://supabase_auth_admin:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      GOTRUE_SITE_URL: ${SITE_URL}
      GOTRUE_URI_ALLOW_LIST: ${ADDITIONAL_REDIRECT_URLS}
      GOTRUE_DISABLE_SIGNUP: ${DISABLE_SIGNUP}
      GOTRUE_JWT_ADMIN_ROLES: service_role
      GOTRUE_JWT_AUD: authenticated
      GOTRUE_JWT_DEFAULT_GROUP_NAME: authenticated
      GOTRUE_JWT_EXP: ${JWT_EXPIRY}
      GOTRUE_JWT_SECRET: ${JWT_SECRET}
      GOTRUE_EXTERNAL_EMAIL_ENABLED: ${ENABLE_EMAIL_SIGNUP}
      GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED: ${ENABLE_ANONYMOUS_USERS}
      GOTRUE_MAILER_AUTOCONFIRM: ${ENABLE_EMAIL_AUTOCONFIRM}
      GOTRUE_SMTP_ADMIN_EMAIL: ${SMTP_ADMIN_EMAIL}
      GOTRUE_SMTP_HOST: ${SMTP_HOST}
      GOTRUE_SMTP_PORT: ${SMTP_PORT}
      GOTRUE_SMTP_USER: ${SMTP_USER}
      GOTRUE_SMTP_PASS: ${SMTP_PASS}
      GOTRUE_SMTP_SENDER_NAME: ${SMTP_SENDER_NAME}
      GOTRUE_MAILER_URLPATHS_INVITE: ${MAILER_URLPATHS_INVITE}
      GOTRUE_MAILER_URLPATHS_CONFIRMATION: ${MAILER_URLPATHS_CONFIRMATION}
      GOTRUE_MAILER_URLPATHS_RECOVERY: ${MAILER_URLPATHS_RECOVERY}
      GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE: ${MAILER_URLPATHS_EMAIL_CHANGE}
      GOTRUE_EXTERNAL_PHONE_ENABLED: ${ENABLE_PHONE_SIGNUP}
      GOTRUE_SMS_AUTOCONFIRM: ${ENABLE_PHONE_AUTOCONFIRM}

  rest:
    container_name: supabase-rest
    image: postgrest/postgrest:v12.2.12
    restart: unless-stopped
    environment:
      PGRST_DB_URI: postgres://authenticator:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      PGRST_DB_SCHEMAS: ${PGRST_DB_SCHEMAS}
      PGRST_DB_ANON_ROLE: anon
      PGRST_JWT_SECRET: ${JWT_SECRET}
      PGRST_DB_USE_LEGACY_GUCS: "false"
      PGRST_APP_SETTINGS_JWT_SECRET: ${JWT_SECRET}
      PGRST_APP_SETTINGS_JWT_EXP: ${JWT_EXPIRY}
    command: ["postgrest"]

  realtime:
    container_name: realtime-dev.supabase-realtime
    image: supabase/realtime:v2.34.47
    restart: unless-stopped
    environment:
      PORT: 4000
      DB_HOST: ${POSTGRES_HOST}
      DB_PORT: ${POSTGRES_PORT}
      DB_USER: supabase_admin
      DB_PASSWORD: ${POSTGRES_PASSWORD}
      DB_NAME: ${POSTGRES_DB}
      DB_AFTER_CONNECT_QUERY: 'SET search_path TO _realtime'
      DB_ENC_KEY: supabaserealtime
      API_JWT_SECRET: ${JWT_SECRET}
      SECRET_KEY_BASE: ${SECRET_KEY_BASE}
      ERL_AFLAGS: -proto_dist inet_tcp
      DNS_NODES: "''"
      RLIMIT_NOFILE: "10000"
      APP_NAME: realtime
      SEED_SELF_HOST: "true"
      RUN_JANITOR: "true"

  storage:
    container_name: supabase-storage
    image: supabase/storage-api:v1.25.7
    restart: unless-stopped
    volumes:
      - ./volumes/storage:/var/lib/storage:z
    environment:
      ANON_KEY: ${ANON_KEY}
      SERVICE_KEY: ${SERVICE_ROLE_KEY}
      POSTGREST_URL: http://rest:3000
      PGRST_JWT_SECRET: ${JWT_SECRET}
      DATABASE_URL: postgres://supabase_storage_admin:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      FILE_SIZE_LIMIT: 52428800
      STORAGE_BACKEND: file
      FILE_STORAGE_BACKEND_PATH: /var/lib/storage
      TENANT_ID: stub
      REGION: stub
      GLOBAL_S3_BUCKET: stub
      ENABLE_IMAGE_TRANSFORMATION: "true"
      IMGPROXY_URL: http://imgproxy:5001

  imgproxy:
    container_name: supabase-imgproxy
    image: darthsim/imgproxy:v3.8.0
    restart: unless-stopped
    volumes:
      - ./volumes/storage:/var/lib/storage:z
    environment:
      IMGPROXY_BIND: ":5001"
      IMGPROXY_LOCAL_FILESYSTEM_ROOT: /
      IMGPROXY_USE_ETAG: "true"
      IMGPROXY_ENABLE_WEBP_DETECTION: ${IMGPROXY_ENABLE_WEBP_DETECTION}

  meta:
    container_name: supabase-meta
    image: supabase/postgres-meta:v0.91.0
    restart: unless-stopped
    environment:
      PG_META_PORT: 8080
      PG_META_DB_HOST: ${POSTGRES_HOST}
      PG_META_DB_PORT: ${POSTGRES_PORT}
      PG_META_DB_NAME: ${POSTGRES_DB}
      PG_META_DB_USER: supabase_admin
      PG_META_DB_PASSWORD: ${POSTGRES_PASSWORD}

  functions:
    container_name: supabase-edge-functions
    image: supabase/edge-runtime:v1.67.4
    restart: unless-stopped
    volumes:
      - ./volumes/functions:/home/deno/functions:Z
    environment:
      JWT_SECRET: ${JWT_SECRET}
      SUPABASE_URL: http://kong:8000
      SUPABASE_ANON_KEY: ${ANON_KEY}
      SUPABASE_SERVICE_ROLE_KEY: ${SERVICE_ROLE_KEY}
      SUPABASE_DB_URL: postgresql://postgres:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      VERIFY_JWT: "${FUNCTIONS_VERIFY_JWT}"
    command: ["start", "--main-service", "/home/deno/functions/main"]

  analytics:
    container_name: supabase-analytics
    image: supabase/logflare:1.14.2
    restart: unless-stopped
    ports:
      - 4000:4000
    environment:
      LOGFLARE_NODE_HOST: 127.0.0.1
      DB_USERNAME: supabase_admin
      DB_DATABASE: ${POSTGRES_DB}
      DB_HOSTNAME: ${POSTGRES_HOST}
      DB_PORT: ${POSTGRES_PORT}
      DB_PASSWORD: ${POSTGRES_PASSWORD}
      DB_SCHEMA: _analytics
      LOGFLARE_PUBLIC_ACCESS_TOKEN: ${LOGFLARE_PUBLIC_ACCESS_TOKEN}
      LOGFLARE_PRIVATE_ACCESS_TOKEN: ${LOGFLARE_PRIVATE_ACCESS_TOKEN}
      LOGFLARE_SINGLE_TENANT: "true"
      LOGFLARE_SUPABASE_MODE: "true"
      LOGFLARE_MIN_CLUSTER_SIZE: 1
      POSTGRES_BACKEND_URL: postgresql://supabase_admin:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      POSTGRES_BACKEND_SCHEMA: _analytics
      LOGFLARE_FEATURE_FLAG_OVERRIDE: multibackend=true

  vector:
    container_name: supabase-vector
    image: timberio/vector:0.28.1-alpine
    restart: unless-stopped
    volumes:
      - ./volumes/logs/vector.yml:/etc/vector/vector.yml:ro,z
      - ${DOCKER_SOCKET_LOCATION}:/var/run/docker.sock:ro,z
    environment:
      LOGFLARE_PUBLIC_ACCESS_TOKEN: ${LOGFLARE_PUBLIC_ACCESS_TOKEN}
    command: ["--config", "/etc/vector/vector.yml"]
    security_opt:
      - "label=disable"

  supavisor:
    container_name: supabase-pooler
    image: supabase/supavisor:2.5.7
    restart: unless-stopped
    ports:
      - ${POSTGRES_PORT}:5432
      - ${POOLER_PROXY_PORT_TRANSACTION}:6543
    volumes:
      - ./volumes/pooler/pooler.exs:/etc/pooler/pooler.exs:ro,z
    environment:
      PORT: 4000
      POSTGRES_PORT: ${POSTGRES_PORT}
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      DATABASE_URL: ecto://supabase_admin:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
      CLUSTER_POSTGRES: "true"
      SECRET_KEY_BASE: ${SECRET_KEY_BASE}
      VAULT_ENC_KEY: ${VAULT_ENC_KEY}
      API_JWT_SECRET: ${JWT_SECRET}
      METRICS_JWT_SECRET: ${JWT_SECRET}
      REGION: local
      ERL_AFLAGS: -proto_dist inet_tcp
      POOLER_TENANT_ID: ${POOLER_TENANT_ID}
      POOLER_DEFAULT_POOL_SIZE: ${POOLER_DEFAULT_POOL_SIZE}
      POOLER_MAX_CLIENT_CONN: ${POOLER_MAX_CLIENT_CONN}
      POOLER_POOL_MODE: transaction
      DB_POOL_SIZE: ${POOLER_DB_POOL_SIZE}
    command: ["/bin/sh", "-c", "/app/bin/migrate && /app/bin/supavisor eval \"$$(cat /etc/pooler/pooler.exs)\" && /app/bin/server"]

volumes:
  db-config:
```
# Kong.yml file
```bash
_format_version: '2.1'
_transform: true

###
### Consumers / Users
###
consumers:
  - username: DASHBOARD
  - username: anon
    keyauth_credentials:
      - key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzU0NTA1MDAwLCJleHAiOjE5MTIyNzE0MDB9.6HTfSydVWzkzSyPBHXL8Z9umdDO667Q7oQdXN2JwYiQ
  - username: service_role
    keyauth_credentials:
      - key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NTQ1MDUwMDAsImV4cCI6MTkxMjI3MTQwMH0.aXWxyL-Xpv-QUd7AKXBSH3vua7QOh4tEXrChw2kj8J0

###
### Access Control List
###
acls:
  - consumer: anon
    group: anon
  - consumer: service_role
    group: admin

###
### Dashboard credentials
###
basicauth_credentials:
  - consumer: DASHBOARD
    username: $DASHBOARD_USERNAME
    password: $DASHBOARD_PASSWORD

###
### API Routes
###
services:
  ## Open Auth routes
  - name: auth-v1-open
    url: http://auth:9999/verify
    routes:
      - name: auth-v1-open
        strip_path: true
        paths:
          - /auth/v1/verify
    plugins:
      - name: cors
  - name: auth-v1-open-callback
    url: http://auth:9999/callback
    routes:
      - name: auth-v1-open-callback
        strip_path: true
        paths:
          - /auth/v1/callback
    plugins:
      - name: cors
  - name: auth-v1-open-authorize
    url: http://auth:9999/authorize
    routes:
      - name: auth-v1-open-authorize
        strip_path: true
        paths:
          - /auth/v1/authorize
    plugins:
      - name: cors

  ## Secure Auth routes
  - name: auth-v1
    _comment: 'GoTrue: /auth/v1/* -> http://auth:9999/*'
    url: http://auth:9999/
    routes:
      - name: auth-v1-all
        strip_path: true
        paths:
          - /auth/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure REST routes
  - name: rest-v1
    _comment: 'PostgREST: /rest/v1/* -> http://rest:3000/*'
    url: http://rest:3000/
    routes:
      - name: rest-v1-all
        strip_path: true
        paths:
          - /rest/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure GraphQL routes
  - name: graphql-v1
    _comment: 'PostgREST: /graphql/v1/* -> http://rest:3000/rpc/graphql'
    url: http://rest:3000/rpc/graphql
    routes:
      - name: graphql-v1-all
        strip_path: true
        paths:
          - /graphql/v1
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: true
      - name: request-transformer
        config:
          add:
            headers:
              - Content-Profile:graphql_public
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon

  ## Secure Realtime routes
  - name: realtime-v1-ws
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime:4000/socket/*'
    url: http://realtime-dev.supabase-realtime:4000/socket
    protocol: ws
    routes:
      - name: realtime-v1-ws
        strip_path: true
        paths:
          - /realtime/v1/
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  - name: realtime-v1-rest
    _comment: 'Realtime: /realtime/v1/* -> ws://realtime:4000/socket/*'
    url: http://realtime-dev.supabase-realtime:4000/api
    protocol: http
    routes:
      - name: realtime-v1-rest
        strip_path: true
        paths:
          - /realtime/v1/api
    plugins:
      - name: cors
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin
            - anon
  ## Storage routes: the storage server manages its own auth
  - name: storage-v1
    _comment: 'Storage: /storage/v1/* -> http://storage:5000/*'
    url: http://storage:5000/
    routes:
      - name: storage-v1-all
        strip_path: true
        paths:
          - /storage/v1/
    plugins:
      - name: cors

  ## Edge Functions routes
  - name: functions-v1
    _comment: 'Edge Functions: /functions/v1/* -> http://functions:9000/*'
    url: http://functions:9000/
    routes:
      - name: functions-v1-all
        strip_path: true
        paths:
          - /functions/v1/
    plugins:
      - name: cors

  ## Analytics routes
  - name: analytics-v1
    _comment: 'Analytics: /analytics/v1/* -> http://logflare:4000/*'
    url: http://analytics:4000/
    routes:
      - name: analytics-v1-all
        strip_path: true
        paths:
          - /analytics/v1/

  ## Secure Database routes
  - name: meta
    _comment: 'pg-meta: /pg/* -> http://pg-meta:8080/*'
    url: http://meta:8080/
    routes:
      - name: meta-all
        strip_path: true
        paths:
          - /pg/
    plugins:
      - name: key-auth
        config:
          hide_credentials: false
      - name: acl
        config:
          hide_groups_header: true
          allow:
            - admin

  ## Protected Dashboard - catch all remaining routes
  - name: dashboard
    _comment: 'Studio: /* -> http://studio:3000/*'
    url: http://studio:3000/
    routes:
      - name: dashboard-all
        strip_path: true
        paths:
          - /
    plugins:
      - name: cors
      - name: basic-auth
        config:
          hide_credentials: true
```
# to download the PGJWT
```bash
docker exec -it <container-name> sh
apt update 
apt install -y git build-essential postgresql-server-dev-16
cd /tmp
pwd
/tmp -- experted output
 git clone https://github.com/michelp/pgjwt.git
ls
pgjwt --expected output
 cd pgjwt
# pwd
/tmp/pgjwt --experted output
make
make install
```
# SQL QUERIES which i used in the postgresql
```bash
psql -h 96.8.121.100 -p 5432 -U supabase_admin -d supabase
-- Connect the database if it is not created
CREATE DATABASE supabase;
\c supabase
-- Create users
CREATE USER supabase_admin             WITH ENCRYPTED PASSWORD 'myaccess';
CREATE USER supabase_auth_admin        WITH ENCRYPTED PASSWORD 'myaccess';
CREATE USER supabase_storage_admin     WITH ENCRYPTED PASSWORD 'myaccess';
CREATE USER supabase_functions_admin   WITH ENCRYPTED PASSWORD 'myaccess';
CREATE USER authenticator              WITH ENCRYPTED PASSWORD 'myaccess';
CREATE USER pgbouncer                  WITH ENCRYPTED PASSWORD 'myaccess';

-- Create roles
CREATE ROLE anon       NOLOGIN;
CREATE ROLE anonymous  NOLOGIN;
CREATE ROLE webuser    NOLOGIN;

-- Alter user privileges
ALTER USER supabase_admin           WITH SUPERUSER;
ALTER USER supabase_auth_admin      WITH SUPERUSER;
ALTER USER supabase_storage_admin   WITH SUPERUSER;
ALTER USER authenticator            WITH SUPERUSER;
ALTER USER pgbouncer                WITH SUPERUSER;
ALTER USER pgbouncer                WITH SUPERUSER;

-- Grant access to databases
GRANT ALL ON DATABASE supabase TO supabase_admin;
GRANT ALL ON DATABASE supabase TO supabase_auth_admin;
GRANT ALL ON DATABASE supabase TO supabase_storage_admin;
GRANT ALL ON DATABASE supabase TO supabase_functions_admin;
GRANT ALL ON DATABASE supabase TO authenticator;
GRANT ALL ON DATABASE supabase TO pgbouncer;
-- Extensions required by Supabase
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pgjwt";  --there are some things you have to do to download this thing . it does not go like this
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "postgis";         -- If using geolocation
CREATE EXTENSION IF NOT EXISTS "plpgsql";
-- Grant Usage on Schema public to anon/web roles
GRANT USAGE ON SCHEMA public TO anon;
GRANT USAGE ON SCHEMA public TO webuser;
GRANT USAGE ON SCHEMA public TO anonymous;
-- Create and Assign Roles to authenticator
GRANT anon TO authenticator;
-- If youre using Supabase Docker, these may be auto-created
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS storage;
CREATE SCHEMA IF NOT EXISTS graphql_public;
CREATE SCHEMA IF NOT EXISTS _analytics;
CREATE SCHEMA IF NOT EXISTS _auth;
-- Grant Privileges on Schemas to Supabase Roles
GRANT ALL ON SCHEMA auth TO supabase_admin;
GRANT ALL ON SCHEMA storage TO supabase_admin;
GRANT ALL ON SCHEMA graphql_public TO supabase_admin;
GRANT ALL ON SCHEMA _analytics TO supabase_admin;
GRANT ALL ON SCHEMA _auth TO supabase_admin;

--  Grant SELECT to anon/webuser (for public APIs)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO anon;
--  Grant Access to anon Role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon;

-- Future Tables: To automatically grant these privileges on tables created in the future, run:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO anon;
note | i have not checked this yet
     V
-- If you have other schemas (like _auth, storage, etc.), repeat the above for each schema:
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA storage TO anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA storage GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO anon;
-- To grant USAGE and SELECT on all sequences in a schema (e.g., public) to a role (e.g., anon), you can use:
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;
--  Grant on all future sequences:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO anon;
CREATE PUBLICATION supabase_realtime FOR ALL TABLES;
ALTER SYSTEM SET wal_level = logical;  -- Then restart PostgreSQL
ALTER PUBLICATION supabase_realtime OWNER TO supabase_admin;
CREATE ROLE authenticated;
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT authenticated TO authenticator;
CREATE ROLE service_role;
GRANT service_role TO authenticator;
GRANT authenticator TO supabase_admin;
CREATE SCHEMA IF NOT EXISTS _supavisor;
CREATE ROLE postgres WITH LOGIN PASSWORD 'myaccess' CREATEDB CREATEROLE;
ALTER ROLE supabase_auth_admin WITH CREATEROLE;
-- Grant usage on the storage schema to the storage admin
GRANT USAGE ON SCHEMA storage TO supabase_storage_admin;

-- Grant all permissions on existing storage tables
GRANT ALL ON ALL TABLES IN SCHEMA storage TO supabase_storage_admin;

-- This is important to ensure future tables also get permissions
ALTER DEFAULT PRIVILEGES IN SCHEMA storage GRANT ALL ON TABLES TO supabase_storage_admin;
```



