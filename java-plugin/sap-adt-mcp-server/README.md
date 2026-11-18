# SAP ADT Relay for Eclipse

This Eclipse plugin executes SAP ADT tools using the credentials entered in the workspace. It opens an outbound mutually authenticated TLS connection to the company relay. Enroll the workspace in the **SAP ADT Relay** view and enroll the desktop MCP client separately.

Build the Eclipse update site with Maven 3.10.0 and JDK 21. The parent POM pins Tycho 5.0.4, and the plugin targets Java 17. The [build instructions](../../docs/verification.md#eclipse-plugin-build) select the Maven executable and cover the standalone package-policy harness.

The build produces an Eclipse update site in `com.sap.adt.mcp.server.site/target/repository` and a ZIP in the same module's `target` directory. The [update site guide](../../docs/eclipse-update-site.md) covers local installation and hosting on GitHub Pages. For enrollment and client configuration, follow the [relay guide](../../README.md).

Adapted from the [SAP ADT MCP Server plugin](https://github.com/YahorNovik/sap-adt-mcp-server). The upstream plugin declares the Apache License, Version 2.0.
