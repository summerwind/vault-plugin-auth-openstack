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
$ vault write sys/plugins/catalog/openstack-auth command="vault-plugin-auth-openstack" sha_256="${SHA256_SUM}"
```

Enable authentication with the plugin.

```
$ vault auth enable -path="openstack" -plugin-name="openstack-auth" plugin
```

## Configuration

In order to authenticate with OpenStack instance, the administrator needs to configure the OpenStack account information and create the role associated with the instance.

Configure the OpenStack account information that is used to attest an instance with OpenStack API. The OpenStack account used here must have permission to read the instance information.

```
$ vault write auth/openstack/config \
    auth_url="${OS_AUTH_URL}" \
    tenant_name="${OS_TENANT_NAME}" \
    username="${OS_USERNAME}" \
    password="${OS_PASSWORD}"
```

Create a role to associate the OpenStack instance with the Vault policies. The following example creates a role named "dev" associated with the vault policy "prod" and "dev". This example role is identified by the vault-role key contained in Metadata of the OpenStack instance, and up to 3 times of authentication can be attempted in 120 seconds after instance is created.

```
$ vault write auth/openstack/role/dev \
    policies="prod,dev" \
    metadata_key="vault-role" \
    auth_period=120
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

## Should I Use This?

This is an experimental plugin. We don't reccomend to use this in your production.
