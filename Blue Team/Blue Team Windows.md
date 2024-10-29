# Active Directory Policy Updates

Enter the following command to display the current password policy for the domain:

```-nocolor
Get-ADDefaultDomainPasswordPolicy
```


Enter the following commands to implement these password policy changes:

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -LockoutObservationWindow 00:15:00
```

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -LockoutDuration 00:15:00
```

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -LockoutThreshold 3
```

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -MaxPasswordAge 365.00:00:00
```

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -MinPasswordAge 3.00:00:00
```

```-nocolor
Set-ADDefaultDomainPasswordPolicy -Identity structureality -MinPasswordLength 12
```

> The time definitions are using the format of D:H:M:S.F where: D = Days (0 to 10675199); H = Hours (0 to 23); M = Minutes (0 to 59); S = Seconds (0 to 59); and F = Fractions of a second (0 to 9999999).

> You can make these same changes through the GUI interface of Group Policy Management.