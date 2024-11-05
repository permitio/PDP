# E2E tests for PDP Offline Mode

### Create Permit Environment

Login to Permit and create a new environment with the following objects:

* Resource 'file' with action 'create'
* Role 'admin' with permission to create 'file'
* User 'user-1' with role 'admin'

Copy the `.env.example` file to `.env` and update the values with the environment details.

### Prepare repo for building PDP image

This would download the Custom OPA and FactDB source code.

```bash
VERSION=<my-local-version> make run-prepare
```
Replace `<my-local-version>` with the version you want to use for the PDP image

### Run the tests

```bash
docker compose up
```


### What does it do

1. Start an online PDP with `PDP_ENABLE_OFFLINE_MODE=True` and connect the `/app/backup` to a volume.
2. Start another offline PDP that is also connected to the same volume.
3. Run a tester that run `permit.check("user-1", "create", "file")` on the online PDP and the offline PDP.
