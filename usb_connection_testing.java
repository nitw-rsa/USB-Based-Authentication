class usb_connection_testing
{
	public static void main()
	{
        System.out.println("Server connection testing.....");
        Scanner sc = new Scanner(System.in);
        String KsType = "PKCS11";
        String configName = (Paths.get(System.getProperty("user.dir"), "pkcs11.cfg")).toString();

        KeyStore ks = null;
        try
		{
            String eTokenDriverPath = "C:/WINDOWS/SYSTEM32/eTpkcs11.dll";
            PKCS11 p11 = PKCS11.getInstance(eTokenDriverPath, "C_GetFunctionList", null, false);
            long[] slotList = p11.C_GetSlotList(true);
            int slotListLength = slotList.length;
            if(slotListLength >= 1)
			{
                String slot = String.valueOf(slotList[0]);
                if(slotListLength > 1)
				{
                    System.out.println("Multiple USB dongles are connected");
                    StringBuilder allSlots = new StringBuilder();
                    for (long l : slotList) allSlots.append(l + " ");
                    System.out.println(allSlots.toString() + "slots detected. Using the first slot found: " + slot);
                }
                if (KsType.equalsIgnoreCase("PKCS11"))
				{
                    Provider p = new SunPKCS11(configName);
                    Security.addProvider(p);
                    ks = KeyStore.getInstance("PKCS11", p);
                    System.out.println("Please enter the USB password: ");
                    String password = sc.nextLine();
                    ks.load(null, password.toCharArray());
                    System.out.println("USB keystore loaded successfully");

                    X509Certificate cert = null;
                    if (ks != null)
					{
                        Enumeration<String> aliasEnum = ks.aliases();
                        if (aliasEnum.hasMoreElements())
						{
                            String alias = aliasEnum.nextElement();
                            cert = (X509Certificate) ks.getCertificate(alias);
                        }
                    }
                    System.out.println("Certificated extracted from USB successfully");
                    String dn = cert.getSubjectX500Principal().getName("RFC2253");
                    String issuer = cert.getIssuerX500Principal().getName("RFC1779");
                    System.out.println("Issuer:        " + issuer);
                }
            }
			else
				System.out.println("USB dongle is not connected");
        }
		catch(Exception e)
		{
            System.out.println(e);
        }
    }
}
