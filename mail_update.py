import releasy
import sys

if __name__ == "__main__":
	preview_only = True if (len(sys.argv) >= 2 and sys.argv[1] == 'preview') else False
	package = releasy.Package()
	package.get_deployment_info()
	package.mail_deployment_update(preview_only=preview_only)