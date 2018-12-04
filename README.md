# Salesforce Releasy - Heroku Add-On

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

## Author
Leon Kempers - lkempers@salesforce.com

## Setup Instructions
We assume you are using this tool on top of the standard Releasy setup, and thus have already set up the Deployment Manifest, requested a Google Sheets API key, and authorized your org through SFDX.

If this is not the case, please go through the setup steps on the [Releasy GitHub](https://git.soma.salesforce.com/lkempers/releasy-heroku) first.

1. On your local machine, run `sfdx force:org:display --verbose -u your@user.com | grep 'Sfdx Auth Url'`. Replace your@user.com with the username you used to authenticate your source org. Note down the Auth URL, which starts with force://.
2. Deploy to Heroku using the button above, and enter the required config variables.
3. After a successful setup, go to your app in the Heroku dashboard and click Settings. Scroll down to Config Vars, click Reveal Config Vars, and add a new key-value pair. The key should be the alias you entered as the value for DEFAULT_SOURCE_ORG, the value should be the Auth URL you wrote down earlier.
4. Go to the Resources tab, open the Heroku Scheduler, and add two new jobs:
	1. `python refresh_components.py`, which runs every hour.
	2. `python mail_update.py`, which runs once every day on your preferred time.

The Heroku add-on is now successfully set up. To manually test its features, run `heroku run bash` from your local machine's shell, and try running the two Python scripts mentioned in step 4.