# Vault Plugin: OpenStack Auth Backend

This is a standalone backend plugin for use with Hashicorp Vault. This plugin allows for OpenStack instances to authenticate with Vault.

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html) and is meant to work with Vault. This guide assumes you have already installed Vault and have a basic understanding of how Vault works.

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Setup

Download the latest plugin binary from the [Releases](https://github.com/summerwind/vault-plugin-auth-openstack/releases) page on GitHub and move the plugin binary into Vault's configured *plugin_directory*.

```
$ mv vault-plugin-auth-openstack /etc/vault/plugins/vault-plugin-auth-openstack
```

Calculate the checksum of the plugin and register it in Vault's plugin catalog. It is highly recommended that you use the published checksums on the Release page to verify integrity.

```
$ export SHA256_SUM=$(shasum -a 256 "/etc/vault/plugins/vault-plugin-auth-openstack" | cut -d' ' -f1)
$ vault write sys/plugins/catalog/auth/openstack \
    command="vault-plugin-auth-openstack" \
    sha_256="${SHA256_SUM}"
```

Enable authentication with the plugin.

```
$ vault auth enable -path="openstack" -plugin-name="openstack" plugin
```

## Configuration

In order to authenticate with OpenStack instance, the administrator needs to configure the OpenStack account information and create the role associated with the instance.

Configure the OpenStack account information that is used to attest an instance with OpenStack API. The OpenStack account used here must have permission to read the instance information.

```
$ vault write auth/openstack/config \
    auth_url="${OS_AUTH_URL}" \
    tenant_name="${OS_TENANT_NAME}" \
    username="${OS_USERNAME}" \
    password="${OS_PASSWORD}" \
    request_address_headers="X-Forwarded-For" \
    request_address_headers="X-Real-Ip"
```

If you want to use the request headers you also have to tune the vault auth plugin:
```
$ vault write sys/auth/openstack/tune \
    passthrough_request_headers="X-Forwarded-For" \
    passthrough_request_headers="X-Real-Ip"
```

Create a role to associate the OpenStack instance with the Vault policies. The following example creates a role named "dev" associated with the vault policy "prod" and "dev". This example role is identified by the vault-role key contained in Metadata of the OpenStack instance, and up to 3 times of authentication can be attempted in 120 seconds after instance is created.

```
$ vault write auth/openstack/role/dev \
    policies="prod,dev" \
    metadata_key="vault-role" \
    auth_period=120 \
    auth_limit=3
```

## Usage

OpenStack instances that use Vault authentication must be created with the metadata key specified in the role.

```
$ openstack server create \
    --flavor ${FLAVOR_NAME} \
    --image ${IMAGE_NAME} \
    --key-name ${KEY_NAME} \
    --property vault-role=dev \
    ${INSTANCE_NAME}
```

After created, instance can be authenticated with Vault as follows. Note that the instance ID must be obtained from config drive or OpenStack metadata server.

```
$ vault write auth/openstack/login instance_id="${INSTANCE_ID}" role="dev"
```

## Authentication flow

This plugin gets the instance information from the OpenStack API and attestates the existence of the instance based on the information. The detailed authentication flow is as follows.

1. Receive the instance ID and the role name through the `vault login` command.
2. Get the instance information from OpenStack API based on the instance ID. If the instance information does not exist, the authentication fails.
3. Get the role configuration based on the role name. If the role configuration does not exist, the authenticate fails.
4. Validate the authentication period specified in the role with the creation time of the instance. If the deadline was exceeded, the authentication fails.
5. Validate the limit of authentication attempt count specified in the role. If authentication exceeds the maximum number of attempts, the authentication fails.
6. Validate the instance IP address with the remote IP address of `vault login`. If address mismatched, the authentication fails. If configured also the IP addresses from the request headers are used for validation.
7. Validate the status of the instance. If the instance is not active, the authentication fails.
8. Validate the role name contained in the metadata of the instance with the key specified in the role configuration. If the key of metadata does not exist or role name is mismatched, the authentication fails.
9. Validate the tenant ID of the instance with the role configuration. If the tenand ID is mismatched, the authentication fails. This validation is performed only if the tenant ID is specified in the role configuration.
9. Validate the user ID of the instance with the role configuration. If the user ID is mismatched, the authentication fails. This validation is performed only if the user ID is specified in the role configuration.

## Development

If you wish to work on this plugin, you'll first need [Go](https://golang.org) and [go-task](https://github.com/go-task/task) installed on your machine.

To build a development version of this plugin, run `task build`. This will put the plugin binary in the current directory.

```
$ task build
```

To run the tests, invoke `task test`.

```
$ task test
```

You can also see the test coverage report as follows.

```
$ task cover
```

## Should I Use This?

This is an experimental plugin. We don't recommend to use this in your production.
