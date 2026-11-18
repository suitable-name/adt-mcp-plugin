# SAP ADT Relay for Eclipse

This Eclipse plugin executes SAP ADT tools through an existing ABAP project's ADT connection. It opens an outbound mutually authenticated TLS connection to the company relay. Enroll the workspace in the **SAP ADT Relay** view and enroll the desktop MCP client separately.

With SAP ADT installed, click **Select ABAP Project** in the relay view and choose an existing ADT workspace project in the Eclipse selector. ADT opens its normal login dialog if needed. Click **Connect Relay** to expose that selected project. Editor tabs and Project Explorer selections do not change the relay's project. Disconnect before choosing another project. Disconnecting or closing the relay view releases its dedicated session while preserving the shared ADT login. If the selected project closes, loses authentication, or changes destination identity, the plugin clears its selection and requires an explicit project selection before reconnecting.

Build the Eclipse update site with Maven 3.10.0 and JDK 21. The parent POM pins Tycho 5.0.4, and the plugin targets Java 17. The build resolves ADT dependencies from SAP's public 2024-03 p2 repository. SAP ADT is required in the runtime Eclipse installation. The [build instructions](../../docs/verification.md#eclipse-plugin-build) select the Maven executable and cover the standalone package-policy harness and live project lifecycle checks.

Keep this reactor's `.mvn/maven.config` in local and CI checkouts. It supplies a temporary Maven Resolver validation workaround for Tycho's nested JAR dependencies, documented with its scope and removal condition in the [developer guide](../../docs/developer-guide.md#contributor-verification).

The build produces an Eclipse update site in `com.sap.adt.mcp.server.site/target/repository` and a ZIP in the same module's `target` directory. The [update site guide](../../docs/eclipse-update-site.md) covers local installation and hosting on GitHub Pages. For enrollment and client configuration, follow the [relay guide](../../README.md).

Adapted from the [SAP ADT MCP Server plugin](https://github.com/YahorNovik/sap-adt-mcp-server). The upstream plugin declares the Apache License, Version 2.0.
