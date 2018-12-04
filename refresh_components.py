import releasy

if __name__ == "__main__":
	md_helper = releasy.MD_Helper(releasy.CONF['SHEET_MANAGER']['SF_USER'], releasy.CONF['SHEET_MANAGER']['SF_PASS'], releasy.CONF['SHEET_MANAGER']['SF_TOKEN'], sandbox=True)
	md_helper.update_sheet()