# apm-java-ldap-plugin

An Elastic APM agent plugin that creates an exit span when a (LDAP) request is done with the JDK LDAP client, e.g. by using JNDI with `com.sun.jndi.ldap.LdapCtxFactory` as `java.naming.factory.initial`.

## Supported Versions

| Plugin | Elastic APM Agent |
| :--- |:------------------|
| 1.0+ | 1.27.0+           |

## Installation

Set the [`plugins_dir`](https://www.elastic.co/guide/en/apm/agent/java/current/config-core.html#config-plugins-dir) agent configuration option and copy the plugin to specified directory.
