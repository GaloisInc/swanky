local state, not global

run `aws configure --profile sieve`

_always_ run `./terraform.sh destroy`. There's a automatic timeout in case you forget.

create `terraform/terraform.tfvars` with

```
ssh_public_key = "ssh-ed25519 ....."
allow_ssh_from = "93.184.216.34/32"
aws_profile = "sieve"
```
the `ssh_public_key` shouldn't have your email (the ssh key comment) at the end.
`allow_ssh_from` is a CIDR, and should be [your IP](https://duckduckgo.com/?q=what+is+my+ip) followed by `/32`

If things break, try running `rm -rf terraform/.terraform terraform/.terraform.lock.hcl` and then `terraform init`.
