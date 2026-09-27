# E2E tests for PDP Offline Mode

### Create Permit Environment

Login to Permit and create a new environment with the following objects:

* Resource 'file' with action 'create'
* Role 'admin' with permission to create 'file'
* User 'user-1' with role 'admin'

Copy the `.env.example` file to `.env` and update the values with the environment details.
Keep `OPAL_STORE_BACKUP_INTERVAL` low: the offline PDP starts as soon as the online one is
healthy, which is before OPAL's default 60s first backup.

### Prepare repo for building PDP image

From the repository root, download the custom OPA source. This clones the private
`permitio/permit-opa` next to the repo over SSH (so it needs access to it) and packs its source
into `custom/custom_opa.tar.gz`, which the image build picks up.

```bash
make prepare
```

### Run the tests

From this directory:

```bash
docker compose up --build
```

Both testers should log `Passed`, `online-pdp` should never log `failed to backup policy store`,
and `docker compose exec online-pdp ls -la /app/backup` should list `policy_store_backup.json`
with no `tmp*.json.tmp` next to it.


### What does it do

1. Start an online PDP with `PDP_ENABLE_OFFLINE_MODE=True` and connect the `/app/backup` to a volume.
2. Start another offline PDP that is also connected to the same volume.
3. Run a tester that run `permit.check("user-1", "create", "file")` on the online PDP and the offline PDP.
