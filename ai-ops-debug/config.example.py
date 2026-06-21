# Compute node credentials per environment.
# Copy this file to config.py and fill in your values.
# config.py is gitignored — never commit real credentials.
#
# Each environment entry needs:
#   domain      — FQDN suffix used to auto-detect the env from a hostname
#   c_username  — SSH service account username
#   c_password  — SSH service account password
#   comphosts   — example hostnames in this environment (optional)

ENVS = {
    "dev": {
        "domain": "compute.dev.your-company.io",
        "c_username": "svc_ops_user",
        "c_password": "CHANGE_ME",
        "comphosts": [
            "comp001.compute.dev.your-company.io",
            "comp002.compute.dev.your-company.io",
        ],
    },
    "staging": {
        "domain": "compute.staging.your-company.io",
        "c_username": "svc_ops_user",
        "c_password": "CHANGE_ME",
        "comphosts": [
            "comp001.compute.staging.your-company.io",
            "comp002.compute.staging.your-company.io",
        ],
    },
    "prod": {
        "domain": "compute.prod.your-company.io",
        "c_username": "svc_ops_user",
        "c_password": "CHANGE_ME",
        "comphosts": [
            "comp001.compute.prod.your-company.io",
            "comp002.compute.prod.your-company.io",
        ],
    },
}

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "ConnectTimeout=30",
    "-o", "ServerAliveInterval=30",
    "-q",
]
