We use sccache to cache our rust build outputs.
We'd like to use sccache's "local" cache backend, in which we point sccache at a folder (that would live on a docker volume), and have it store its things there.
Unfortunately, sccache's "local" cache backend is not safe for multiple concurrent accesses.
To solve this, we use sccache's webdav backend, pointing it at an nginx instance.
