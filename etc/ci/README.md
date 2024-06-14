To setup a CI runner, follow the standard instructions for setting up a gitlab CI runner, and then:

NOTE: this is not a secure/locked-down setup. Do not allow untrusted users to submit CI jobs to this system.

1. Setup the filesystems. Using XFS is preferable but ZFS is okay (we don't care about data integrity for this use-case, so the improved performance of XFS is worth it.) If ZFS is used, be sure to enable the ZFS docker storage backend, and make sure that the block-cloning ZFS feature is enabled.
2. Install Nix (WITH THE NIX DAEMON) (Pass the --daemon option to the nix install script). If you're running ZFS, then /nix should be its own ZFS dataset
3. Create the /var/lib/swanky-sccache directory, and give it 0777 permissions
4. Register the runner, make sure to give it the `docker-nix` tag, with the `docker` executor
5. Modify the `/etc/gitlab-runner/config.toml` file for the runner you just added. The `runners.docker.volumes` key should contain:
    ```
    [
        "/nix/store:/nix/store:ro",
        "/nix/var/nix/db:/nix/var/nix/db:ro",
        "/nix/var/nix/daemon-socket:/nix/var/nix/daemon-socket:ro",
        "/nix/var/nix/profiles/default:/nix/var/nix/profiles/default:ro",
        "/var/lib/swanky-sccache:/var/lib/swanky-sccache",
    ]
    ```.
5. Restart the gitlab-runner service

# If things break...
## How to purge the caches
1. Pause the CI runner in the gitlab CI settings interface for the repo
2. SSH to the CI runner (and use htop to make sure that all CI jobs have finished)
3. Run `nix-collect-garbage` and `rm -rf /var/lib/swanky-sccache/*`
4. Un-pause the CI runner

# How to use the cache
When using the cache, it's important to remember that _multiple_ CI jobs might be using the cache at once.
As a result, operations which manipulate the cache should be atomic.

To make things easier, we never automatically expire entries in the CI cache.
If the cache gets too big, follow the instructions above to manually purge it.

# Cache Design
Unlike many CI caching setups which use remote (e.g. over HTTP) caches, Swanky's caching setup operates exclusively on the CI runner's local disk (via a docker volume). This makes our CI much simpler _and_ much faster.

## Hashing Files
Like with other CI caching schemes, Swanky's CI setup needs to hash files. As some of our compiled files can get quite large, reading an entire file to hash it can be slow (both due to CPU and due to I/O).

We avoid re-hashing files that we've already hashed by caching the hashes. Once we've hashed a file, we store its hash, along with a cache key, in the file's [xattrs](https://en.wikipedia.org/wiki/Extended_file_attributes). For a cache key, we use (among some other metadata) the file's `mtime` (last  modified timestamp) and it's [inode number](https://en.wikipedia.org/wiki/Inode). This allows us to detect if a file's hash cache is stale, which lets us re-hash it.

## Copying Files
As part of the CI caching setup, we need to copy files from the cache to `./target`. To do this efficiently, we want to use [copy-on-write](https://en.wikipedia.org/wiki/Copy-on-write) semantics on filesystems that support it (such as XFS and recent ZFS). This results in copies that take $O(1)$ time, regardless of the size of the file. To achieve this, we use the [`copy_file_range()`](https://www.man7.org/linux/man-pages/man2/copy_file_range.2.html) system call.

(Note: `copy_file_range()` differs from a [hard link](https://en.wikipedia.org/wiki/Hard_link) in that, with `copy_file_range()`, changing the new file won't affect the old file.)

## Caching Builds
To cache builds, our goal is to take advantage of Cargo's caching infrastructure (rather than supplanting it with something like [sccache](https://github.com/mozilla/sccache)). Roughly, we want to 'zip' up `./target` after a CI run has completed and 'unzip' the most recent `./target` directory before the CI run starts.

Each packed `./target` directory is associated with the git commit that generated it. On a subsequent CI job, we look through the git log and unpack the `./target` directory associated with the most recent git commit.

### Content-Addressable Storage

While we could, in theory, actually use `.zip` files for (un)packing a `./target` directory, decompressing a zip file takes time linear in the size of the output file (in contrast to the logical copying procedure described above).

Instead, when we pack a `./target` directory, we just record the hashes (using the hashing scheme above) of the `./target` files. For each `./target` file, we copy (using the above copying scheme) the file to `/cache/<HASH OF FILE>/`, if that path doesn't already exist. (This provides a [content-adressable storage scheme](https://en.wikipedia.org/wiki/Content-addressable_storage).)

To unpack a `./target` directory, we go through the manifest and copy the relevant files from `/cache/<HASH>` to `./target` using `copy_file_range()`. After copying the file, since we know what its hash is (because we looked up the file by hash), we populate the file's xattr hash cache.

### Modification Times

Cargo uses file modification time metadata to determine when a file has been changed. By default, copying a file will set its modification time to the current time. This would tell cargo that every copied file has changed, and it'd invalidate the cache.

To work around this, for files in `./target`, we record the modification time when the file was created (in a previous CI run), and then change the modification time of the copied file to the recorded time. For input files (non-gitignored files), we record the hashes and modification times of each input file. When we unpack  a `./target` folder, we compare the hashes of the files in the git repo against the recorded hashes. If the hashes are equal, then we set the modification time to the recorded modification time. Otherwise, we set the modification time to the current recorded time.
