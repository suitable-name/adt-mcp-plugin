# Eclipse Update Site

Tycho builds a p2 repository that Eclipse can install from a local disk or an HTTPS server. The repository distributes the Eclipse plugin. The Rust relay runs separately on your company server.

## Install in Eclipse

1. Open the Eclipse installation you use for SAP ADT. Select **Help → Install New Software… → Add…** and enter **SAP ADT MCP Relay** as the name.
2. Choose the location that matches your distribution.

   | Distribution | What to select |
   | --- | --- |
   | Published update site | Paste the HTTPS URL for the directory containing `p2.index` into **Location**. |
   | Local update-site ZIP | Click **Archive…** and choose `com.sap.adt.mcp.server.site-1.0.0-SNAPSHOT.zip`. A downloaded release copy works the same way. |
   | Local build directory | Click **Local…** and choose the generated `repository` directory containing `p2.index`. |

   After the Maven build, the ZIP and the `repository` directory are siblings under `java-plugin/sap-adt-mcp-server/com.sap.adt.mcp.server.site/target/`. [Build instructions](../README.md)
3. Click **Add**. Expand **SAP ADT MCP Relay** and select the feature with that name. Click **Next**, review the installation details and license, and click **Finish**. Review any publisher trust prompt according to your organization's policy, then restart Eclipse when prompted. [Eclipse installation guide](https://help.eclipse.org/latest/topic/org.eclipse.platform.doc.user/tasks/tasks-124.htm)
4. Confirm **SAP ADT MCP Relay** appears under **Help → About Eclipse IDE → Installation Details → Installed Software**. To connect it to the relay, follow the [operator manual](operator-manual.md).

Eclipse saves the site under **Preferences → Install/Update → Available Software Sites**. Keep the hosted URL enabled and use **Help → Check for Updates** when the maintainer publishes a newer feature version. If you installed from a ZIP, add the hosted URL once to receive future updates through that site. [Eclipse update instructions](https://help.eclipse.org/latest/topic/org.eclipse.platform.doc.user/tasks/tasks-120.htm)

## Publish on GitHub Pages

### Publish With the Manual Workflow

The workflow publishes a complete Pages site for this repository. If the repository already hosts other Pages content, include that content in the deployment before switching publishing sources. [GitHub Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)

1. Put the workflow and the modified plugin on the default branch, keeping `.github/workflows/` and `java-plugin/` at the repository root. If your plugin is a separate local clone, import a copy of its files excluding its inner `.git` directory, or configure a submodule pinned to a pushed commit in a fork the runner can read. Before running the workflow, browse `java-plugin/sap-adt-mcp-server/` on GitHub. Confirm it contains the updated `pom.xml`, `com.sap.adt.mcp.server.plugin/gson-2.11.0.jar`, and `tests/PackagePolicyRegression.java`. [Eclipse update site workflow](../.github/workflows/eclipse-update-site.yml)
2. In the repository, open **Settings → Pages → Build and deployment** and set **Source** to **GitHub Actions**. This is a one-time setting. [Configure the Pages publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
3. Open **Actions → Eclipse Update Site → Run workflow**. Choose the default branch and click **Run workflow** to start the build. You need write access to trigger it. [Run a workflow manually](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
4. Open the run to follow its jobs. The build runs Maven 3.10.0 `clean verify` with JDK 21 and executes the standalone Java package-policy harness. A successful run on the default branch proceeds to Pages deployment. You can select another branch to run the build and harness alone.
5. After deployment, copy the update-site URL from the run summary. You can also append `eclipse/` to the site's base URL from **Settings → Pages**. A project site typically has the update URL `https://OWNER.github.io/REPOSITORY/eclipse/`. To verify it, open `p2.index` under that URL. Enter the directory URL ending in `/eclipse/` in Eclipse and confirm **SAP ADT MCP Relay** appears.

For the next update, trigger the workflow again after the new code reaches the default branch. The workflow supplies a UTC version qualifier with second precision. Users keep the same update URL and choose **Help → Check for Updates**.

### Alternative for a Separate Distribution Repository

If you already build the plugin locally and want a separate repository to host the files, you can use branch publishing there. Copy the entire generated `repository` directory to `eclipse/` on that repository's publishing branch. Keep `eclipse/p2.index`, its metadata, `features/`, and `plugins/` together. Add an empty `.nojekyll` file at the branch root. In **Settings → Pages**, select **Deploy from a branch**, choose the publishing branch and **/(root)**, then click **Save**. The update URL is that repository's Pages URL followed by `/eclipse/`. [Create a Pages site](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site)

**Company access.** GitHub Free supports Pages from public repositories. Paid plans can also publish from private repositories, and the resulting site can still be public. GitHub Enterprise Cloud offers private project sites for eligible organization repositories. For a restricted site, test a download from the intended Eclipse installation, including any required sign-in. An internal HTTPS server can serve the same `eclipse/` directory on the company domain. [GitHub Pages availability](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site) · [Private Pages access](https://docs.github.com/en/enterprise-cloud@latest/pages/getting-started-with-github-pages/changing-the-visibility-of-your-github-pages-site)

**GitHub Releases.** To distribute a downloadable copy, attach the generated update-site ZIP as a release asset. Users download it and select **Archive…** in Eclipse. For an update URL they can keep between releases, share the Pages directory URL. [Eclipse software site locations](https://help.eclipse.org/latest/topic/org.eclipse.platform.doc.user/tasks/tasks-127.htm)
