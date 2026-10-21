# Production archive provider: a distinct box-control persistent application.
# root-control/host-deploy provisions the protected application execution grant;
# this declaration never selects a host username, UID, GID or station identity.
application(
    name="archive-mirror",
    description="Archive provider with independent retained storage",
    persistent=True,
    multiple_instances=False,
    execution_identity="application",
    start_policy="externally-controlled",
    writable_mounts=("archive-data",),
    preparation_revision="production-archive-data-v2-execution-identity",
    preparation=(program(
        name="prepare",
        command=("/usr/bin/true",),
        execution_timeout_seconds=60,
        mounts={"archive-data": "/var/lib/archive-mirror"},
    ),),
    programs=(
        program(
            name="server",
            command=("/usr/bin/python3", "-B", "-m", "zog.archive_mirror",
                     "serve", "--host", "127.0.0.1", "--port", "8080"),
            mounts={"archive-data": "/var/lib/archive-mirror"},
            environment={
                "DJANGO_SETTINGS_MODULE": "zog.archive_mirror.settings",
                "ARCHIVE_MIRROR_STATE": "/var/lib/archive-mirror",
                "ARCHIVE_MIRROR_CONFIGURATION": "/var/lib/archive-mirror/configuration.json",
                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",
            },
        ),
        program(
            name="refresh-scheduler",
            command=("/usr/bin/python3", "-B", "-m", "zog.archive_mirror", "scheduler"),
            mounts={"archive-data": "/var/lib/archive-mirror"},
            environment={
                "DJANGO_SETTINGS_MODULE": "zog.archive_mirror.settings",
                "ARCHIVE_MIRROR_STATE": "/var/lib/archive-mirror",
                "ARCHIVE_MIRROR_CONFIGURATION": "/var/lib/archive-mirror/configuration.json",
                "ARCHIVE_MIRROR_REQUIRE_OWNERSHIP": "1",
            },
        ),
    ),
)
