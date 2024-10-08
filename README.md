# Graph EasyPIM
Something to make Entra ID PIM easier for end-users. 

You can install the module [from PowerShell Gallery](https://www.powershellgallery.com/packages/Graph.EasyPIM/). 

```powershell
Install-Module -Name Graph.EasyPIM
```

Not using PowerShell Gallery? Download the source code from this 👇 repo, or get started with PowerShell Gallery following the instructions [here](https://learn.microsoft.com/en-gb/powershell/gallery/getting-started?view=powershellget-3.x).

Tested primarily on Windows with PowerShell 7.4, but I don't see any reason why it wouldn't work on macOS and Linux. It currently has the following cmdlets:

- `Enable-PIMRole` - enable (activate) Entra ID PIM roles
- `Disable-PIMRole` - disable (deactivate) Entra ID PIM roles

## Pre-requisite modules
This modules depends upon the following. 

- "Microsoft.Graph.Authentication"
- "Microsoft.Graph.Identity.Governance"
- "Microsoft.PowerShell.ConsoleGuiTools"

If it weren't for these, this module wouldn't exist! Thank you 😍 to the creators of these, especially `Microsoft.PowerShell.ConsoleGuiTools` which is what I use to drive things. 🙏

## Screenshots

Running `Enable-PIMRole` lists all the available and active Entra ID PIM roles for the user.

![image-20241006172734455](assets/image-20241006172734455.png)

Press `SPACE` to select <u>one or more</u> entries to activate them. (Currently deactivating isn't supported coz the only thing I really do is activate roles; and then deactivate on their own!)

![image-20241006172840346](assets/image-20241006172840346.png)

Press `ENTER`. This is what starts the activation process. The previous step only selects the ones we wish to activate.

Enter a reason or ticket number if the role requires it. 

![image-20241006173010679](assets/image-20241006173010679.png)

Wait a bit for it to show the final status. 

![image-20241006173033656](assets/image-20241006173033656.png)

That's it! 

Way faster than the Entra ID portal. And moreover, you can select more than 1 role at a go. 