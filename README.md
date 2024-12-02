# adfs-ls
Retrieve ADFS relying parties names from positive hits iterating through a list of targets.

# What are ADFS Relying Parties?
Relying parties are external applications or services that trust the ADFS server for authentication. These services use ADFS as an identity provider (IdP) to allow single sign-on (SSO) for users within the domain. Essentially, ADFS acts as the intermediary between the user's credentials and the relying parties, enabling seamless authentication without requiring the user to log in separately to each application.

These could be external services like Salesforce, AWS, or other SaaS platforms that rely on ADFS for user authentication.

Many organizations also use ADFS to authenticate users for internal applications such as intranet portals, custom web apps, or legacy systems.

If the organization integrates with cloud platforms (e.g., Office 365, Azure AD), the relying party dropdown might include options for those services.

