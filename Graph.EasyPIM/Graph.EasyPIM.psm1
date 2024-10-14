# Common variables
## The scopes that we need. Identified these from the Graph API docs + while testing. 
$requiredScopesArrayRoles = @("RoleEligibilitySchedule.Read.Directory","RoleEligibilitySchedule.ReadWrite.Directory",
                                "RoleManagement.Read.Directory","RoleManagement.Read.All","RoleManagement.ReadWrite.Directory",
                                "RoleAssignmentSchedule.ReadWrite.Directory","RoleAssignmentSchedule.Remove.Directory"
)

$requiredScopesArrayGroups = @("PrivilegedEligibilitySchedule.Read.AzureADGroup","PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
                                "PrivilegedAccess.Read.AzureADGroup","PrivilegedAccess.ReadWrite.AzureADGroup",
                                "RoleManagementPolicy.Read.AzureADGroup"
)

$requiredScopesArray = $requiredScopesArrayRoles + $requiredScopesArrayGroups

# Thanks https://www.pdq.com/blog/change-powershell-colors/ for showing me where to get these colors
$colorParams = @{}
if ($host.PrivateData.VerboseForegroundColor -ne "-1") {
    $colorParams.ForegroundColor = $host.PrivateData.VerboseForegroundColor
}

if ($host.PrivateData.VerboseBackgroundColor -ne "-1") {
    $colorParams.BackgroundColor = $host.PrivateData.VerboseBackgroundColor
}

function Enable-PIMRole {
    param(
        [Parameter(Mandatory=$false)]
        [Alias("SkipReason")]
        [switch]$SkipJustification,

        [Parameter(Mandatory=$false)]
        [Alias("Reason")]
        [string]$Justification,

        [Parameter(Mandatory=$false)]
        [string]$TicketingSystem,

        [switch]$RefreshEligibleRoles
    )

    <#
    .DESCRIPTION
    Enable Entra ID PIM roles via an easy to use TUI (Text User Interface). Only supports enabling; not disabling. Use Disable-PIMRole to disable.

    If a role needs a reason/ justification you can either enter one, or press enter to go with "xxx", or type something and end with * to use it for all the activations.

    .PARAMETER SkipJustification
    Optional. If specified, it sets the reason/ justifaction for activation to be "xxx".

    .PARAMETER Justification
    Optional. If specified, it sets the reason/ justifaction for activation to whatever is input.

    .PARAMETER TicketingSystem
    Optional. If specified, it sets the tickting system (for role activations that need a ticket number) to be whatever is input.

    .PARAMETER RefreshEligibleRoles
    Optional. By default, eligible roles are only checked if it's been more than 30 mins since the last invocation. If you want to check before that, use this switch. 

    #>

    begin {
        Write-Host ""
        $colorParams = $script:colorParams

        [System.Version]$installedVersion = (Get-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version
        [System.Version]$availableVersion = (Find-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version

        if ($installedVersion -and $availableVersion -and ($installedVersion -lt $availableVersion)) {
            Write-Host @colorParams "🎉 A newer version of this module is available in PowerShell Gallery"
        }

        try {
            Connect-MgGraph -Scopes $script:requiredScopesArray -NoWelcome -ErrorAction Stop

        } catch {
            throw "$($_.Exception.Message)"
        }

        $context = Get-MgContext

        $scopes = $context.scopes

        if ($scopes -notcontains "Directory.ReadWrite.All") {
            foreach ($requiredScope in $script:requiredScopesArray) {
                if ($requiredScope -notin $scopes) {
                    Write-Warning "Required scope '$requiredScope' missing"
                }
            }
        }

        $userId = (Get-MgUser -UserId $context.Account).Id

        if ($RefreshEligibleRoles) {
            $needsUpdating = $true

        } else {
            # Only pull in the eligible roles if needed; else use the cached info
            $currentTime = (Get-Date).ToUniversalTime()
            $lastUpdatedRoles = $script:lastUpdatedRoles

            if ($null -ne $lastUpdatedRoles) {
                $lastUpdatedTimespan = New-TimeSpan -Start $lastUpdatedRoles -End $currentTime
            
                if ($lastUpdatedTimespan.TotalMinutes -gt 30) {
                    $needsUpdating = $true
                
                } else {
                    $needsUpdating = $false
                    if ($lastUpdatedTimespan.TotalMinutes -eq 1) {
                        $minutes = "a minute"

                    } else {
                        $minutes = "$([int]$lastUpdatedTimespan.TotalMinutes) minutes"
                    }
                }
        
            } else {
                $needsUpdating = $true
            }
        }

        try {
            if ($needsUpdating) {
                Write-Host @colorParams "🥷 Fetching all eligible & active Entra ID roles. This will take a few minutes."

                Write-Progress -Activity "Fetching all eligible Entra ID roles" -Id 0
                [array]$myEligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$userId'" -ErrorAction Stop
                [array]$script:myEligibleRoles = $myEligibleRoles

            } else {
                Write-Host @colorParams "⏳ Not fetching eligible Entra ID roles & their policies as it has only been $minutes since we last checked."
                Write-Host @colorParams "🫵 You can re-run with the -RefreshEligibleRoles switch to force a refresh."
                [array]$myEligibleRoles = $script:myEligibleRoles
            }

            Write-Progress -Activity "Fetching all active Entra ID roles" -Id 0
            [array]$myActiveRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$userId'" -ErrorAction Stop
            
        } catch {
            throw "Error fetching roles: $($_.Exception.Message)"
        }

        Write-Progress -Id 0 -Completed

        # Create a cache of assignments. This is faster as I can lookup a bunch of them beforehand.
        # All roles have the same policy (settings) assigned to them. And a user could have the same role assigned in more than one way - e.g. various admin units. 
        $policyAssignmentHashRoles = @{}
        # I must set scopeId to '/' coz if I search for a specific scopeId it errors: Attempted to perform an unauthorized operation.
        $searchSnippetMain = "scopeType eq 'DirectoryRole' and scopeId eq '/' and ("
        $searchSnippetsArray = @()

        # Filter has a max length (not sure what) so I will do it in batches of 5. 
        # A temp variable I keep incrementing
        $counter = 0
        # Total number of entries for this scope
        $totalCount = $myEligibleRoles.Count

        # Loop through the entries
        if ($needsUpdating) {
            Write-Host @colorParams "🚀 Fetching all role assignment settings. This will take a few minutes."

            foreach ($roleObj in $myEligibleRoles) {
                $counter++
                $roleDefinitionId = $roleObj.RoleDefinitionId

                # An array where I keep adding the snippets
                $searchSnippetsArray += "roleDefinitionId eq '$roleDefinitionId'"

                Write-Progress -Activity "Fetching..." -Id 0 -Status "${counter}/${totalCount}" -PercentComplete $($counter*100/$totalCount)
    
                # In batches of 5, or if the counter has reached the end...
                if ($counter % 5 -eq 0 -or $counter -ge $totalCount) {
                    # ... construct the search snippet
                    $searchSnippet = $searchSnippetMain + $($searchSnippetsArray -join ' or ') + ")"
    
                    # Do the search
                    try {
                        $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -All -Filter $searchSnippet -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
                    
                    } catch {
                        throw "Error fetching settings assignments: $($_.Exception.Message)"
                    }
                    
                    # And add it to the hash
                    foreach ($result in $policyAssignment) {
                        $policyAssignmentHashRoles[$($result.RoleDefinitionId)] = $result
                    }
    
                    # Initialize the array again
                    $searchSnippetsArray = @()
                }
            }
            
            Write-Progress -Id 0 -Completed

            # Fetching all the policies
            Write-Host @colorParams "🧙 Fetching all role settings."

            try {
                $policyObjsHashRoles = @{}

                Get-MgPolicyRoleManagementPolicy -All -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" -ExpandProperty Rules -ErrorAction Stop | ForEach-Object {
                    $policyObjsHashRoles[$($_.Id)] = $_
                }

            } catch {
                throw "Error fetching all the settings: $($_.Exception.Message)"
            }

            $script:policyAssignmentHashRoles = $policyAssignmentHashRoles
            $script:policyObjsHashRoles = $policyObjsHashRoles

            $script:lastUpdatedRoles = $currentTime  # Set the lastUpdated timestamp since we have successfully updated the cache

        } else {
            $policyAssignmentHashRoles = $script:policyAssignmentHashRoles
            $policyObjsHashRoles = $script:policyObjsHashRoles

        }
    }

    process {
        Write-Host ""
        $policyEnablementRulesCache = @{}
        $roleDefinitionsCache = @{}

        $defaultJustification = "xxx"

        # I use these for showing progress
        [int]$counter = 0
        [int]$totalCount = $myEligibleRoles.Count

        $roleStates = foreach ($roleObj in $myEligibleRoles) {
            $counter++
            $percentageComplete = ($counter/$totalCount)*100

            $roleDefinitionId = $roleObj.RoleDefinitionId
            $roleName = $roleObj.RoleDefinition.DisplayName
            $roleDirectoryScopeId = $roleObj.DirectoryScopeId

            $roleDefinitionsCache[$roleDefinitionId] = $roleName

            $timespanArray = @()
            $roleExpired = $false
            $roleAssignmentType = "Inactive"

            Write-Progress -Activity "Processing role '$roleName'" -Id 0 -PercentComplete $percentageComplete -Status "$counter/$totalCount"

            $activeRoleObj = $null
            $activeRoleObj = $myActiveRoles | Where-Object { $_.RoleDefinitionId -eq "$roleDefinitionId" -and $_.DirectoryScopeId -eq "$roleDirectoryScopeId" }

            if ($activeRoleObj) {
                Write-Progress -Activity "Role is active; calculating time remaining..." -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
                Start-Sleep -Milliseconds 200   # a stupid hack coz Write-Progress doesn't display outside loops apparently! https://github.com/PowerShell/PowerShell/issues/5741
                Write-Progress -Activity "Role is active; calculating time remaining..." -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
                
                # Double checking coz during my testing I ran into instances where this was sometimes incomplete
                if ($activeRoleObj.ScheduleInfo.Expiration.EndDateTime) {
                    # $roleAssignmentType = $activeRoleObj.AssignmentType
                    $roleAssignmentType = "Active"

                    $timeSpan = New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $activeRoleObj.ScheduleInfo.Expiration.EndDateTime
                    if ($timeSpan.Days -gt 0) {
                        if ($timeSpan.Days -eq 1) {
                            $timespanArray += "$($timeSpan.Days) day"
    
                        } else {
                            $timespanArray += "$($timeSpan.Days) days"
                        }
                    }
    
                    if ($timeSpan.Hours -gt 0) {
                        if ($timeSpan.Hours -eq 1) {
                            $timespanArray += "$($timeSpan.Hours) hour"
    
                        } else {
                            $timespanArray += "$($timeSpan.Hours) hours"
                        }
                    }
    
                    if ($timeSpan.Minutes -gt 0) {
                        if ($timeSpan.Minutes -eq 1) {
                            $timespanArray += "$($timeSpan.Minutes) minute"
    
                        } else {
                            $timespanArray += "$($timeSpan.Minutes) minutes"
                        }
                    }
    
                    # Just in case there's a delay between getting the states and when I calculate this...
                    if ($timeSpan.Ticks -lt 0) { 
                        $roleExpired = $true 
                    }

                } else {
                    $roleExpired = $true 
                }

                Write-Progress -Id 1 -Completed

            } else {
                $roleExpired = $true
            }

            # Using the roledefinitionid, find the policy assignment on this role
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyassignment?view=graph-rest-1.0
            
            <#
            $roleDirectoryScopeId = $roleObj.DirectoryScopeId
            
            Write-Progress -Activity "Fetching policy assignment of role '$roleName'" -Id 2 -PercentComplete $percentageComplete -Status "$counter/$totalCount"
            try {
                $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -All -Filter "scopeId eq '$roleDirectoryScopeId' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleDefinitionId'" -ErrorAction Stop

            } catch {
                Write-Warning "Error fetching policy assignments for '$roleName': $($_.Exception.Message)"
                continue
            }
            #>
            # Skipping the above code as I now cache it before hand. This is faster than doing individual lookups.
            $policyAssignment = $policyAssignmentHashRoles[$roleDefinitionId]

            # From there find the policy :)
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicy?view=graph-rest-1.0
            $policyId = $policyAssignment.PolicyId

            # Look it up in the cached table; but in the off chance that it isn't there, look it up directly
            if ($policyObjsHashRoles.Keys -contains $policyId) {
                $policyObj = $policyObjsHashRoles[$policyId]

            } else {
                Write-Progress -Activity "Fetching settings '$(($policyId -split '_')[2])'" -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
                Start-Sleep -Milliseconds 200   # a stupid hack coz Write-Progress doesn't display outside loops apparently! https://github.com/PowerShell/PowerShell/issues/5741
                Write-Progress -Activity "Fetching settings '$(($policyId -split '_')[2])'" -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
    
                try {
                    $policyObj = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $policyId -ExpandProperty Rules -ErrorAction Stop
                    
                    $policyObjsHashRoles[$policyId] = $policyObj # caching it for within this current execution
                    $script:policyObjsHashRoles[$policyId] = $policyObj  # caching it for future invocations of the module

                } catch {
                    Write-Warning "Error fetching settings id '$policyId': $($_.Exception.Message)"
                    continue
                }
            }

            # The policy is what defines the max duration of the role and other factors. We are interested in here are the rules
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule?view=graph-rest-1.0
            
            # The 'Expiration_EndUser_Assignment' rule in the policy is what defines the maximum duration
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0
            $expirationRule = ($policyObj.Rules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }).AdditionalProperties

            if ($expirationRule.maximumDuration -match "^PT") {
                # Thanks https://stackoverflow.com/a/57296616
                $timeSpan = [System.Xml.XmlConvert]::ToTimeSpan($expirationRule.maximumDuration)
                
                $maxDurationArray = @()

                if ($timeSpan.Days -gt 0) {
                    if ($timeSpan.Days -eq 1) {
                        $maxDurationArray += "$($timeSpan.Days) day"

                    } else {
                        $maxDurationArray += "$($timeSpan.Days) days"
                    }
                }

                if ($timeSpan.Hours -gt 0) {
                    if ($timeSpan.Hours -eq 1) {
                        $maxDurationArray += "$($timeSpan.Hours) hour"

                    } else {
                        $maxDurationArray += "$($timeSpan.Hours) hours"
                    }
                }

                if ($timeSpan.Minutes -gt 0) {
                    if ($timeSpan.Minutes -eq 1) {
                        $maxDurationArray += "$($timeSpan.Minutes) minute"

                    } else {
                        $maxDurationArray += "$($timeSpan.Minutes) minutes"
                    }
                }

                $maxDuration = $maxDurationArray -join ' '

            } else {
                $maxDuration = $expirationRule.maximumDuration
            }

            # Repeat, but for the enablement rules
            if ($policyEnablementRulesCache.Keys -contains $policyId) {
                $enablementRule = $policyEnablementRulesCache.$policyId

            } else {
                # The 'Expiration_EndUser_Assignment' rule in the policy is what defines the maximum duration
                # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0
                $enablementRule = ($policyObj.Rules | Where-Object { $_.Id -eq "Enablement_EndUser_Assignment" }).AdditionalProperties.enabledRules
                $policyEnablementRulesCache.$policyId = $enablementRule
            }

            # Thanks to https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/assign-roles-different-scopes
            if ($roleDirectoryScopeId -eq '/') {
                $roleScope = "Directory"

            } elseif ($roleDirectoryScopeId -match "\/administrativeUnits\/") {
                $adminUnitId = $roleDirectoryScopeId -replace '\/administrativeUnits\/',''
                try {
                    $adminUnitName = (Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $adminUnitId -ErrorAction Stop).DisplayName

                } catch {
                    $adminUnitName = $adminUnitId
                }

                $roleScope = "$adminUnitName (Admin Unit)"

            } else {
                $appScope = $roleDirectoryScopeId -replace '\/',''
                $roleScope = "$appScope (App)"
            }

            Write-Progress -Completed -Id 1

            [pscustomobject][ordered]@{
                "RoleName" = $roleName
                "Status" = $roleAssignmentType
                "ExpiresIn" = if (!($roleExpired)) {
                    # Take only the topmost entry (day or hour in case of more than one)
                    if ($timespanArray.Count -gt 1) {
                        "~" + $timespanArray[0]
                    } else {
                        $timespanArray[0]
                    }
                } # Tweak the output to to save some space

                "MaxDuration" = $maxDuration
                "EnablementRules" = $enablementRule -join '|' -replace 'Justification','Reason' -replace 'Ticketing','Ticket' -replace 'MultiFactorAuthentication','MFA'
                "Scope" = $roleScope
                "More" = [pscustomobject]@{
                    "More" = [pscustomobject]@{
                        "RoleDefinitionId" = $roleObj.RoleDefinitionId
                        "DirectoryScopeId" = $roleDirectoryScopeId
                        "MaxDuration" = $expirationRule.maximumDuration
                        "EnablementRule" = $enablementRule
                        "ActiveMinutes" = if (!($roleExpired)) { (New-TimeSpan -End (Get-Date).ToUniversalTime() -Start $activeRoleObj.ScheduleInfo.StartDateTime).TotalMinutes }    
                    }
                } # Two levels to hide this and save some space
            }
        }

        Write-Progress -Completed -Id 0

        $userSelections = $roleStates | Out-ConsoleGridView -Title "List of active & eligible Entra ID PIM roles (count: $totalCount)"

        # Let's ask for the required info upfront
        $justificationsHash = @{}
        $ticketSystemHash = @{}
        $ticketNumberHash = @{}

        # I use this for tidying up some of the output later; find the longest entry in the selections
        $longestRoleLength = ($userSelections.RoleName | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1).Length
        $longestScopeLength = ($userSelections.Scope | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1).Length

        $rolesWereDisabled = $false
        foreach ($selection in $userSelections) {
            if ($selection.Status -ne "Inactive") {
                if ($selection.More.More.ActiveMinutes -le 5) {
                    Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  👉  " -f $($selection.RoleName), $($selection.Scope))
                    Write-Host @colorParams "Cannot disable the role as it must be active for at least 5 minutes."
                    continue
                }

                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  👉  " -f $($selection.RoleName), $($selection.Scope))
                Write-Host @colorParams "Disabling role (so we can enable it again)"

                $params = @{
                    Action = "selfDeactivate"
                    PrincipalId = $userId
                    RoleDefinitionId = $selection.More.More.RoleDefinitionId
                    DirectoryScopeId = $selection.More.More.DirectoryScopeId
                }

                try {
                    $requestObj = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                
                    $rolesWereDisabled = $true
            
                } catch {
                    Write-Error "Error deactivating '$($selection.RoleName)': $($_.Exception.Message)"
                }
            }
        }

        if ($rolesWereDisabled) {
            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before continuing" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }

            Write-Progress -Completed
            Write-Host ""
        }

        foreach ($selection in $userSelections) {
            # Skip activating active roles that have been active for less than 5 mins
            # Coz we wouldn't have been able to disable them above to reactivate
            if ($selection.Status -ne "Inactive" -and $selection.More.More.ActiveMinutes -le 5) { continue }

            if ($selection.More.More.EnablementRule -contains "Justification") {
                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  📋  " -f $($selection.RoleName), $($selection.Scope))

                if ($SkipJustification) {
                    $justificationsHash[$($selection.RoleName)] = "$defaultJustification"
                    Write-Host @colorParams "Reason will be set to: $defaultJustification"

                } elseif ($Justification.Length -ne 0) {
                    $justificationsHash[$($selection.RoleName)] = $Justification
                    Write-Host @colorParams "Reason will be set to: $Justification"

                } else {
                    $justificationInput = Read-Host "Please provide a reason"
                
                    # If the justitication ends with an asterisk or is empty, use it for everything else that follows...
                    if ($justificationInput -match '\*$' -or $justificationInput.Length -eq 0) {
                        # First, remove the asterisk
                        $justificationInput = $justificationInput -replace '\*$',''

                        # Then check whether anything remains. This is to cater to situations where someone enters * or *** etc. 
                        # If after removing the asterisk there's nothing, then set it to $defaultJustification for all. This is basically equivalent to -SkipJustification
                        if ($justificationInput.Length -eq 0) {
                            $justificationInput = "$defaultJustification"
                            $justificationsHash[$($selection.RoleName)] = $justificationInput
                        }
                        
                        # Set the justification for everything that follows to be this
                        $Justification = $justificationInput
                        $justificationsHash[$($selection.RoleName)] = $justificationInput

                    } else {
                        $justificationsHash[$($selection.RoleName)] = $justificationInput
                    }
                }
            }

            if ($selection.More.More.EnablementRule -contains "Ticketing") {
                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  📋  " -f $($selection.RoleName), $($selection.Scope))

                $ticketNumberHash[$($selection.RoleName)] = Read-Host "Please provide a ticket number"

                if ($TicketingSystem.Length -ne 0) {
                    Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  📋  " -f $($selection.RoleName), $($selection.Scope))
                    $ticketingSystemInput = Read-Host "Please provide the ticketing system name"

                    # If the justitication ends with an asterisk, use it for everything else that follows...
                    if ($ticketingSystemInput -match '\*$') {
                        $ticketingSystemInput = $ticketingSystemInput -replace '\*$',''
                        $TicketingSystem = $ticketingSystemInput
                    }

                    $ticketSystemHash[$($selection.RoleName)] = $ticketingSystemInput

                } else {
                    $ticketSystemHash[$($selection.RoleName)] = $TicketingSystem
                }
            }
        }

        if ($userSelections.Count -ne 0) {
            Write-Host ""
        }

        # An array to capture each of the items we action below
        $requestObjsArray = @()

        foreach ($selection in $userSelections) {
            # Skip activating active roles that have been active for less than 5 mins
            # Coz we wouldn't have been able to disable them above to reactivate
            if ($selection.Status -ne "Inactive" -and $selection.More.More.ActiveMinutes -le 5) { continue }

            Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  👉  " -f $($selection.RoleName), $($selection.Scope))
            Write-Host @colorParams "Enabling for $($selection.MaxDuration)"

            $params = @{
                Action = "selfActivate"
                PrincipalId = $userId
                RoleDefinitionId = $selection.More.More.RoleDefinitionId
                DirectoryScopeId = $selection.More.More.DirectoryScopeId

                ScheduleInfo = @{
                    StartDateTime = Get-Date
                    Expiration = @{
                        Type = "AfterDuration"
                        Duration = $selection.More.More.MaxDuration
                    }
                }
            }

            if ($selection.More.More.EnablementRule -contains "Justification") {
                $params.Justification = $justificationsHash[$($selection.RoleName)]
            }

            if ($selection.More.More.EnablementRule -contains "Ticketing") {
                $params.TicketInfo = @{
                    TicketNumber = $ticketNumberHash[$($selection.RoleName)]
                    TicketSystem = $ticketSystemHash[$($selection.RoleName)]
                }
            }

            try {
                $requestObj = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop

                # Show the output to screen

                <#
                $requestObj | Select-Object -Property @{
                    "Name" = "Role";
                    "Expression" = { $roleDefinitionsCache[$($_.RoleDefinitionId)] }
                },Status
                #>
            
                # And add it to an array so we can loop over in the end
                $requestObjsArray += $requestObj
        
            } catch {
                Write-Error "Error activating '$($selection.RoleName)': $($_.Exception.Message)"
            }
        }

        if ($requestObjsArray.Count -ne 0) {
            Write-Host ""

            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before showing the final status" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }

            Write-Progress -Completed
        }

        $counter = 0
        $totalCount = $requestObjsArray.Count

        $finalOutput = foreach ($requestObj in $requestObjsArray) {
            $counter++
            Write-Progress "Fetching status of role '$($roleDefinitionsCache[$($requestObj.RoleDefinitionId)])'" -PercentComplete $($counter*100/$totalCount) -Status "$counter/$totalCount" 
            
            Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -UnifiedRoleAssignmentScheduleRequestId $requestObj.Id | Select-Object -Property @{
                "Name" = "Role";
                "Expression" = { $roleDefinitionsCache[$($_.RoleDefinitionId)] }
            },Status 
        }

        $finalOutput | Format-Table
    }
}

# This is a copy paste of Enable-PIMRole with some bits removed...
# It's very simple compared to Enable-PIMRole
function Disable-PIMRole {
    begin {
        Write-Host ""
        $colorParams = $script:colorParams
        
        [System.Version]$installedVersion = (Get-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version
        [System.Version]$availableVersion = (Find-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version

        if ($installedVersion -and $availableVersion -and ($installedVersion -lt $availableVersion)) {
            Write-Host @colorParams "🎉 A newer version of this module is available in PowerShell Gallery"
        }

        try {
            Connect-MgGraph -Scopes $script:requiredScopesArray -NoWelcome -ErrorAction Stop

        } catch {
            throw "$($_.Exception.Message)"
        }

        $context = Get-MgContext

        $scopes = $context.scopes

        if ($scopes -notcontains "Directory.ReadWrite.All") {
            foreach ($requiredScope in $script:requiredScopesArray) {
                if ($requiredScope -notin $scopes) {
                    Write-Warning "Required scope '$requiredScope' missing"
                }
            }
        }

        $userId = (Get-MgUser -UserId $context.Account).Id

        try {
            Write-Host @colorParams "🥷 Fetching all active Entra ID roles. This should be pretty quick!"

            Write-Progress -Activity "Fetching all active Entra ID roles" -Id 0
            [array]$myActiveRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$userId'" -ErrorAction Stop
            
        } catch {
            throw "Error fetching roles: $($_.Exception.Message)"
        }

        Write-Progress -Id 0 -Completed
    }

    process {
        Write-Host ""

        $roleDefinitionsCache = @{}

        # I use these for showing progress
        [int]$counter = 0
        [int]$totalCount = $myActiveRoles.Count

        $roleStates = foreach ($roleObj in $myActiveRoles) {
            $counter++
            $percentageComplete = ($counter/$totalCount)*100

            $roleDefinitionId = $roleObj.RoleDefinitionId
            $roleName = $roleObj.RoleDefinition.DisplayName
            $roleDirectoryScopeId = $roleObj.DirectoryScopeId

            $roleDefinitionsCache[$roleDefinitionId] = $roleName

            $timespanArray = @()
            $roleExpired = $false
            $roleAssignmentType = "Inactive"

            Write-Progress -Activity "Processing role '$roleName'" -Id 0 -PercentComplete $percentageComplete -Status "$counter/$totalCount"

            Write-Progress -Activity "Calculating role durations" -ParentId 0 -Id 1 -Status "Waiting..."
            Start-Sleep -Milliseconds 200   # a stupid hack coz Write-Progress doesn't display outside loops apparently! https://github.com/PowerShell/PowerShell/issues/5741
            Write-Progress -Activity "Calculating role durations" -ParentId 0 -Id 1 -Status "Waiting..."

            $activeRoleObj = $myActiveRoles | Where-Object { $_.RoleDefinitionId -eq "$roleDefinitionId" }
                
            # Double checking coz during my testing I ran into instances where this was sometimes incomplete
            if ($activeRoleObj.ScheduleInfo.Expiration.EndDateTime) {
                # $roleAssignmentType = $activeRoleObj.AssignmentType
                $roleAssignmentType = "Active"

                $timeSpan = New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $activeRoleObj.ScheduleInfo.Expiration.EndDateTime
                if ($timeSpan.Days -gt 0) {
                    if ($timeSpan.Days -eq 1) {
                        $timespanArray += "$($timeSpan.Days) day"

                    } else {
                        $timespanArray += "$($timeSpan.Days) days"
                    }
                }

                if ($timeSpan.Hours -gt 0) {
                    if ($timeSpan.Hours -eq 1) {
                        $timespanArray += "$($timeSpan.Hours) hour"

                    } else {
                        $timespanArray += "$($timeSpan.Hours) hours"
                    }
                }

                if ($timeSpan.Minutes -gt 0) {
                    if ($timeSpan.Minutes -eq 1) {
                        $timespanArray += "$($timeSpan.Minutes) minute"

                    } else {
                        $timespanArray += "$($timeSpan.Minutes) minutes"
                    }
                }

                # Just in case there's a delay between getting the states and when I calculate this...
                if ($timeSpan.Ticks -lt 0) { 
                    $roleExpired = $true 
                }

            } else {
                $roleExpired = $true 
            }

            # Thanks to https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/assign-roles-different-scopes
            if ($roleDirectoryScopeId -eq '/') {
                $roleScope = "Directory"

            } elseif ($roleDirectoryScopeId -match "\/administrativeUnits\/") {
                $adminUnitId = $roleDirectoryScopeId -replace '\/administrativeUnits\/',''
                try {
                    $adminUnitName = (Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $adminUnitId -ErrorAction Stop).DisplayName

                } catch {
                    $adminUnitName = $adminUnitId
                }

                $roleScope = "$adminUnitName (Admin Unit)"

            } else {
                $appScope = $roleDirectoryScopeId -replace '\/',''
                $roleScope = "$appScope (App)"
            }

            Write-Progress -Id 1 -Completed

            [pscustomobject][ordered]@{
                "RoleName" = $roleName
                "Status" = $roleAssignmentType
                "ExpiresIn" = if (!($roleExpired)) {
                    # Take only the topmost entry (day or hour in case of more than one)
                    if ($timespanArray.Count -gt 1) {
                        "~" + $timespanArray[0]
                    } else {
                        $timespanArray[0]
                    }
                } # Tweak the output to to save some space

                "Scope" = $roleScope
                "More" = [pscustomobject]@{
                    "More" = [pscustomobject]@{
                        "RoleDefinitionId" = $roleObj.RoleDefinitionId
                        "DirectoryScopeId" = $roleObj.DirectoryScopeId
                        "ActiveMinutes" = (New-TimeSpan -End (Get-Date).ToUniversalTime() -Start $activeRoleObj.ScheduleInfo.StartDateTime).TotalMinutes
                    }
                    }  # Two levels to hide this and save some space
            }
        }

        Write-Progress -Id 0 -Completed

        $userSelections = $roleStates | Out-ConsoleGridView -Title "List of active Entra ID PIM roles"

        # I use this for tidying up some of the output later; find the longest entry in the selections
        $longestRoleLength = ($userSelections.RoleName | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1).Length
        $longestScopeLength = ($userSelections.Scope | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1).Length

        # An array to capture each of the items we action below
        $requestObjsArray = @()

        foreach ($selection in $userSelections) {
            if ($selection.More.More.ActiveMinutes -le 5) {
                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  👉  " -f $($selection.RoleName), $($selection.Scope))
                Write-Host @colorParams "Cannot disable the role as it must be active for at least 5 minutes."
                continue
            }

            Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength} [{1,-$longestScopeLength}]  👉  " -f $($selection.RoleName), $($selection.Scope))
            Write-Host @colorParams "Disabling role"

            $params = @{
                Action = "selfDeactivate"
                PrincipalId = $userId
                RoleDefinitionId = $selection.More.More.RoleDefinitionId
                DirectoryScopeId = $selection.More.More.DirectoryScopeId
            }

            try {
                $requestObj = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
            
                # And add it to an array so we can loop over in the end
                $requestObjsArray += $requestObj
        
            } catch {
                Write-Error "Error deactivating '$($selection.RoleName)': $($_.Exception.Message)"
            }
        }

        if ($requestObjsArray.Count -ne 0) {
            Write-Host ""

            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before showing the final status" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }

            Write-Progress -Completed
        }

        $counter = 0
        $totalCount = $requestObjsArray.Count

        $finalOutput = foreach ($requestObj in $requestObjsArray) {
            $counter++
            Write-Progress "Fetching status of role '$($roleDefinitionsCache[$($requestObj.RoleDefinitionId)])'" -PercentComplete $($counter*100/$totalCount) -Status "$counter/$totalCount" 
            
            Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -UnifiedRoleAssignmentScheduleRequestId $requestObj.Id | Select-Object -Property @{
                "Name" = "Role";
                "Expression" = { $roleDefinitionsCache[$($_.RoleDefinitionId)] }
            },Status 
        }

        $finalOutput | Format-Table
    }
}

function Enable-PIMGroup {
    param(
        [Parameter(Mandatory=$false)]
        [Alias("SkipReason")]
        [switch]$SkipJustification,

        [Parameter(Mandatory=$false)]
        [Alias("Reason")]
        [string]$Justification,

        [Parameter(Mandatory=$false)]
        [string]$TicketingSystem,

        [switch]$RefreshEligibleGroups
    )

    <#
    .DESCRIPTION
    Enable Entra ID PIM groups via an easy to use TUI (Text User Interface). Only supports enabling; not disabling. Use Disable-PIMGroup to disable.

    If a group needs a reason/ justification you can either enter one, or press enter to go with "xxx", or type something and end with * to use it for all the activations.

    .PARAMETER SkipJustification
    Optional. If specified, it sets the reason/ justifaction for activation to be "xxx".

    .PARAMETER Justification
    Optional. If specified, it sets the reason/ justifaction for activation to whatever is input.

    .PARAMETER TicketingSystem
    Optional. If specified, it sets the tickting system (for group activations that need a ticket number) to be whatever is input.

    .PARAMETER RefreshEligibleGroups
    Optional. By default, eligible groups are only checked if it's been more than 30 mins since the last invocation. If you want to check before that, use this switch. 
    #>

    begin {
        Write-Host ""
        $colorParams = $script:colorParams

        [System.Version]$installedVersion = (Get-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version
        [System.Version]$availableVersion = (Find-Module Graph.EasyPIM -ErrorAction SilentlyContinue).Version

        if ($installedVersion -and $availableVersion -and ($installedVersion -lt $availableVersion)) {
            Write-Host @colorParams "🎉 A newer version of this module is available in PowerShell Gallery"
        }

        try {
            Connect-MgGraph -Scopes $script:requiredScopesArray -NoWelcome -ErrorAction Stop

        } catch {
            throw "$($_.Exception.Message)"
        }

        $context = Get-MgContext

        $scopes = $context.scopes

        if ($scopes -notcontains "Directory.ReadWrite.All") {
            foreach ($requiredScope in $script:requiredScopesArray) {
                if ($requiredScope -notin $scopes) {
                    Write-Warning "Required scope '$requiredScope' missing"
                }
            }
        }

        $userId = (Get-MgUser -UserId $context.Account).Id

        if ($RefreshEligibleGroups) {
            $needsUpdating = $true

        } else {
            # Only pull in the eligible Groups if needed; else use the cached info
            $currentTime = (Get-Date).ToUniversalTime()
            $lastUpdatedGroups = $script:lastUpdatedGroups

            if ($null -ne $lastUpdatedGroups) {
                $lastUpdatedTimespan = New-TimeSpan -Start $lastUpdatedGroups -End $currentTime
            
                if ($lastUpdatedTimespan.TotalHours -gt 8) {
                    $needsUpdating = $true
                
                } else {
                    $needsUpdating = $false
                    if ($lastUpdatedTimespan.TotalHours -eq 1) {
                        $minutes = "an hour"

                    } elseif ($lastUpdatedTimespan.TotalHours -eq 0) {
                        if ($lastUpdatedTimespan.TotalMinutes -eq 1) {
                            $minutes = "a minute"
    
                        } else {
                            $minutes = "$([int]$lastUpdatedTimespan.TotalMinutes) minutes"
                        }
                    } 
                    else {
                        $minutes = "$([int]$lastUpdatedTimespan.TotalHours) hours"
                    }
                }
        
            } else {
                $needsUpdating = $true
            }
        }

        try {
            if ($needsUpdating) {
                Write-Host @colorParams "🥷 Fetching all eligible & active Entra ID groups. This will take a few minutes."

                Write-Progress -Activity "Fetching all eligible Entra ID groups" -Id 0
                [array]$myEligibleGroups = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -All -Filter "principalId eq '$userId'" -ExpandProperty Group -ErrorAction Stop
                [array]$script:myEligibleGroups = $myEligibleGroups

            } else {
                Write-Host @colorParams "⏳ Not fetching eligible Entra ID groups & their policies as it has only been $minutes since we last checked."
                Write-Host @colorParams "🫵 You can re-run with the -RefreshEligibleGroups switch to force a refresh."
                [array]$myEligibleGroups = $script:myEligibleGroups
            }

            Write-Progress -Activity "Fetching all active Entra ID groups" -Id 0
            [array]$myActiveGroups = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -All -Filter "principalId eq '$userId'" -ExpandProperty Group -ErrorAction Stop
            
        } catch {
            throw "Error fetching groups: $($_.Exception.Message)"
        }

        Write-Progress -Id 0 -Completed

        # Create a cache of assignments. This is faster as I can lookup a bunch of them beforehand.
        $policyAssignmentHashGroupsOwner = @{}
        $policyAssignmentHashGroupsMember = @{}
        # The scopeId is the groupId, so I add this on later
        $searchSnippetMain = "scopeType eq 'Group' and "
        
        # Filter has a max length (not sure what) so I will do it in batches of 5. 
        # A temp variable I keep incrementing
        $counter = 0
        # Total number of entries for this scope
        $totalCount = $myEligibleGroups.Count

        # Loop through the entries
        # Below doesn't work... loop through each group & do accessId member and owner
        if ($needsUpdating) {
            Write-Host @colorParams "🧙 Fetching all group settings. This will take a few minutes."

            foreach ($groupRoleObj in $myEligibleGroups) {
                $counter++
                $groupId = $groupRoleObj.GroupId

                $searchSnippet = $searchSnippetMain + "scopeId eq '$groupId'"
    
                Write-Progress -Activity "$($groupRoleObj.Group.DisplayName)" -Id 0 -Status "${counter}/${totalCount}" -PercentComplete $($counter*100/$totalCount)
                
                # Do the search
                try {
                    $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -All -Filter $searchSnippet -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
                
                } catch {
                    throw "Error fetching settings assignments: $($_.Exception.Message)"
                }
                
                # And add it to the hash. There are two results - member and owner
                foreach ($result in $policyAssignment) {
                    if ($result.RoleDefinitionId -eq "member") {
                        $policyAssignmentHashGroupsMember[$groupId] = $result

                    } elseif ($result.RoleDefinitionId -eq "owner") {
                        $policyAssignmentHashGroupsOwner[$groupId] = $result

                    }
                }
            }

            $script:policyAssignmentHashGroupsOwner = $policyAssignmentHashGroupsOwner
            $script:policyAssignmentHashGroupsMember = $policyAssignmentHashGroupsMember

            $script:lastUpdatedGroups = $currentTime  # Set the lastUpdated timestamp since we have successfully updated the cache

        } else {
            $policyAssignmentHashGroupsOwner = $script:policyAssignmentHashGroupsOwner
            $policyAssignmentHashGroupsMember = $script:policyAssignmentHashGroupsMember

        }

        Write-Progress -Id 0 -Completed
    }

    process {
        Write-Host ""

        $defaultJustification = "xxx"

        # I use these for showing progress
        [int]$counter = 0
        [int]$totalCount = $myEligibleGroups.Count
        $groupNamesCache = @{}

        $groupStates = foreach ($groupRoleObj in $myEligibleGroups) {
            $counter++
            $percentageComplete = ($counter/$totalCount)*100

            $groupId = $groupRoleObj.GroupId
            $groupName = $groupRoleObj.Group.DisplayName
            $groupNamesCache[$groupId] = $groupName

            $accessId = $groupRoleObj.AccessId

            $timespanArray = @()
            $groupRoleExpired = $false
            $groupRoleAssignmentType = "Inactive"

            Write-Progress -Activity "Processing group '$groupName'" -Id 0 -PercentComplete $percentageComplete -Status "$counter/$totalCount"

            $activeGroupRoleObj = $null
            $activeGroupRoleObj = $myActiveGroups | Where-Object { $_.GroupId -eq "$groupId" -and $_.AccessId -eq "$accessId" }

            if ($activeGroupRoleObj) {
                Write-Progress -Activity "Group is active; calculating time remaining..." -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
                Start-Sleep -Milliseconds 200   # a stupid hack coz Write-Progress doesn't display outside loops apparently! https://github.com/PowerShell/PowerShell/issues/5741
                Write-Progress -Activity "o is active; calculating time remaining..." -ParentId 0 -Id 1 -Status "Waiting..." -PercentComplete $percentageComplete
                
                # Double checking coz during my testing I ran into instances where this was sometimes incomplete
                if ($activeGroupRoleObj.ScheduleInfo.Expiration.EndDateTime) {
                    $groupRoleAssignmentType = "Active"

                    $timeSpan = New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $activeGroupRoleObj.ScheduleInfo.Expiration.EndDateTime
                    if ($timeSpan.Days -gt 0) {
                        if ($timeSpan.Days -eq 1) {
                            $timespanArray += "$($timeSpan.Days) day"
    
                        } else {
                            $timespanArray += "$($timeSpan.Days) days"
                        }
                    }
    
                    if ($timeSpan.Hours -gt 0) {
                        if ($timeSpan.Hours -eq 1) {
                            $timespanArray += "$($timeSpan.Hours) hour"
    
                        } else {
                            $timespanArray += "$($timeSpan.Hours) hours"
                        }
                    }
    
                    if ($timeSpan.Minutes -gt 0) {
                        if ($timeSpan.Minutes -eq 1) {
                            $timespanArray += "$($timeSpan.Minutes) minute"
    
                        } else {
                            $timespanArray += "$($timeSpan.Minutes) minutes"
                        }
                    }
    
                    # Just in case there's a delay between getting the states and when I calculate this...
                    if ($timeSpan.Ticks -lt 0) { 
                        $groupRoleExpired = $true 
                    }

                } else {
                    $groupRoleExpired = $true 
                }

                Write-Progress -Id 1 -Completed

            } else {
                $groupRoleExpired = $true
            }

            # Using the roledefinitionid, find the policy assignment on this role
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyassignment?view=graph-rest-1.0
            
            $policyAssignment = if ($accessId -eq "member") { $policyAssignmentHashGroupsMember[$groupId] } else { $policyAssignmentHashGroupsOwner[$groupId] }
            $policyObj = $policyAssignment.Policy

            # The policy is what defines the max duration of the role and other factors. We are interested in here are the rules
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule?view=graph-rest-1.0
            
            # The 'Expiration_EndUser_Assignment' rule in the policy is what defines the maximum duration
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0
            $expirationRule = ($policyObj.Rules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }).AdditionalProperties

            if ($expirationRule.maximumDuration -match "^PT") {
                # Thanks https://stackoverflow.com/a/57296616
                $timeSpan = [System.Xml.XmlConvert]::ToTimeSpan($expirationRule.maximumDuration)
                
                $maxDurationArray = @()

                if ($timeSpan.Days -gt 0) {
                    if ($timeSpan.Days -eq 1) {
                        $maxDurationArray += "$($timeSpan.Days) day"

                    } else {
                        $maxDurationArray += "$($timeSpan.Days) days"
                    }
                }

                if ($timeSpan.Hours -gt 0) {
                    if ($timeSpan.Hours -eq 1) {
                        $maxDurationArray += "$($timeSpan.Hours) hour"

                    } else {
                        $maxDurationArray += "$($timeSpan.Hours) hours"
                    }
                }

                if ($timeSpan.Minutes -gt 0) {
                    if ($timeSpan.Minutes -eq 1) {
                        $maxDurationArray += "$($timeSpan.Minutes) minute"

                    } else {
                        $maxDurationArray += "$($timeSpan.Minutes) minutes"
                    }
                }

                $maxDuration = $maxDurationArray -join ' '

            } else {
                $maxDuration = $expirationRule.maximumDuration
            }

            # Repeat, but for the enablement rules
            $enablementRule = ($policyObj.Rules | Where-Object { $_.Id -eq "Enablement_EndUser_Assignment" }).AdditionalProperties.enabledRules

            Write-Progress -Completed -Id 1

            [pscustomobject][ordered]@{
                "GroupName" = $groupName
                "Status" = $groupRoleAssignmentType
                "Type" = if ($accessId -eq "member") { "Member" } else { "Owner" }
                "ExpiresIn" = if (!($groupRoleExpired)) {
                    # Take only the topmost entry (day or hour in case of more than one)
                    if ($timespanArray.Count -gt 1) {
                        "~" + $timespanArray[0]
                    } else {
                        $timespanArray[0]
                    }
                } # Tweak the output to to save some space

                "MaxDuration" = $maxDuration
                "EnablementRules" = $enablementRule -join '|' -replace 'Justification','Reason' -replace 'Ticketing','Ticket' -replace 'MultiFactorAuthentication','MFA'
                "More" = [pscustomobject]@{
                    "More" = [pscustomobject]@{
                        "AccessId" = $accessId
                        "GroupId" = $groupRoleObj.GroupId
                        "MaxDuration" = $expirationRule.maximumDuration
                        "EnablementRule" = $enablementRule
                        "ActiveMinutes" = if (!($groupRoleExpired)) { (New-TimeSpan -End (Get-Date).ToUniversalTime() -Start $activeGroupRoleObj.ScheduleInfo.StartDateTime).TotalMinutes }
                    }
                }  # Two levels to hide this and save some space
            }
        }

        Write-Progress -Completed -Id 0

        $userSelections = $groupStates | Out-ConsoleGridView -Title "List of active & eligible Entra ID PIM groups (count: $totalCount)"

        # Let's ask for the required info upfront
        $justificationsHash = @{}
        $ticketSystemHash = @{}
        $ticketNumberHash = @{}

        # I use this for tidying up some of the output later; find the longest entry in the selections
        $longestRoleLength = ($userSelections.GroupName | Sort-Object -Property { $_.Length } -Descending | Select-Object -First 1).Length

        $groupsWereDisabled = $false
        foreach ($selection in $userSelections) {
            if ($selection.Status -ne "Inactive") {
                if ($selection.More.More.ActiveMinutes -le 5) {
                    Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  👉  " -f $($selection.GroupName))
                    Write-Host @colorParams "Cannot disable the group as it must be active for at least 5 minutes."
                    continue
                }

                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  👉  " -f $($selection.GroupName))
                Write-Host @colorParams "Disabling group (so we can enable it again)"

                $params = @{
                    accessId = $selection.More.More.AccessId
                    action = "selfDeactivate"
                    principalId = $userId
                    groupId = $selection.More.More.GroupId
                }

                try {
                    $requestObj = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                
                    $groupsWereDisabled = $true
            
                } catch {
                    Write-Error "Error deactivating '$($selection.GroupName)': $($_.Exception.Message)"
                }
            }
        }

        if ($groupsWereDisabled) {
            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before continuing" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }

            Write-Progress -Completed
            Write-Host ""
        }

        foreach ($selection in $userSelections) {
            # Skip activating active roles that have been active for less than 5 mins
            # Coz we wouldn't have been able to disable them above to reactivate
            if ($selection.Status -ne "Inactive" -and $selection.More.More.ActiveMinutes -le 5) { continue }

            if ($selection.More.More.EnablementRule -contains "Justification") {
                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  📋  " -f $($selection.GroupName))

                if ($SkipJustification) {
                    $justificationsHash[$($selection.GroupName)] = "$defaultJustification"
                    Write-Host @colorParams "Reason will be set to: $defaultJustification"

                } elseif ($Justification.Length -ne 0) {
                    $justificationsHash[$($selection.GroupName)] = $Justification
                    Write-Host @colorParams "Reason will be set to: $Justification"

                } else {
                    $justificationInput = Read-Host "Please provide a reason"
                
                    # If the justitication ends with an asterisk or is empty, use it for everything else that follows...
                    if ($justificationInput -match '\*$' -or $justificationInput.Length -eq 0) {
                        # First, remove the asterisk
                        $justificationInput = $justificationInput -replace '\*$',''

                        # Then check whether anything remains. This is to cater to situations where someone enters * or *** etc. 
                        # If after removing the asterisk there's nothing, then set it to $defaultJustification for all. This is basically equivalent to -SkipJustification
                        if ($justificationInput.Length -eq 0) {
                            $justificationInput = "$defaultJustification"
                            $justificationsHash[$($selection.GroupName)] = $justificationInput
                        }
                        
                        # Set the justification for everything that follows to be this
                        $Justification = $justificationInput
                        $justificationsHash[$($selection.GroupName)] = $justificationInput

                    } else {
                        $justificationsHash[$($selection.GroupName)] = $justificationInput
                    }
                }
            }

            if ($selection.More.More.EnablementRule -contains "Ticketing") {
                Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  📋  " -f $($selection.GroupName))

                $ticketNumberHash[$($selection.GroupName)] = Read-Host "Please provide a ticket number"

                if ($TicketingSystem.Length -ne 0) {
                    Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  📋  " -f $($selection.GroupName))
                    $ticketingSystemInput = Read-Host "Please provide the ticketing system name"

                    # If the justitication ends with an asterisk, use it for everything else that follows...
                    if ($ticketingSystemInput -match '\*$') {
                        $ticketingSystemInput = $ticketingSystemInput -replace '\*$',''
                        $TicketingSystem = $ticketingSystemInput
                    }

                    $ticketSystemHash[$($selection.GroupName)] = $ticketingSystemInput

                } else {
                    $ticketSystemHash[$($selection.GroupName)] = $TicketingSystem
                }
            }
        }

        if ($userSelections.Count -ne 0) {
            Write-Host ""
        }

        # An array to capture each of the items we action below
        $requestObjsArray = @()

        foreach ($selection in $userSelections) {
            # Skip activating active roles that have been active for less than 5 mins
            # Coz we wouldn't have been able to disable them above to reactivate
            if ($selection.Status -ne "Inactive" -and $selection.More.More.ActiveMinutes -le 5) { continue }

            Write-Host -NoNewline @colorParams ("{0,-$longestRoleLength}  👉  " -f $($selection.GroupName))
            Write-Host @colorParams "Enabling for $($selection.MaxDuration)"

            $params = @{
                accessId = $selection.More.More.AccessId
                action = "selfActivate"
                principalId = $userId
                groupId = $selection.More.More.GroupId

                scheduleInfo = @{
                    startDateTime = Get-Date
                    expiration = @{
                        type = "AfterDuration"
                        duration = $selection.More.More.MaxDuration
                    }
                }
            }

            if ($selection.More.More.enablementRule -contains "Justification") {
                $params.justification = $justificationsHash[$($selection.GroupName)]
            }

            if ($selection.More.More.enablementRule -contains "Ticketing") {
                $params.ticketInfo = @{
                    ticketNumber = $ticketNumberHash[$($selection.GroupName)]
                    ticketSystem = $ticketSystemHash[$($selection.GroupName)]
                }
            }

            try {
                $requestObj = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
            
                # And add it to an array so we can loop over in the end
                $requestObjsArray += $requestObj
        
            } catch {
                Write-Error "Error activating '$($selection.GroupName)': $($_.Exception.Message)"
            }
        }

        if ($requestObjsArray.Count -ne 0) {
            Write-Host ""

            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before showing the final status" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }

            Write-Progress -Completed
        }

        $counter = 0
        $totalCount = $requestObjsArray.Count

        $finalOutput = foreach ($requestObj in $requestObjsArray) {
            $counter++
            Write-Progress "Fetching status of group '$($groupNamesCache[$($requestObj.GroupId)])'" -PercentComplete $($counter*100/$totalCount) -Status "$counter/$totalCount" 
            
            Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -PrivilegedAccessGroupAssignmentScheduleRequestId $requestObj.Id | Select-Object -Property @{
                "Name" = "Group";
                "Expression" = { $groupNamesCache[$($_.GroupId)] }
            }, @{
                "Name" = "Type";
                "Expression" = { if ($_.AccessId -eq "member") { "Member" } else { "Owner" } }
            }, Status 
        }

        $finalOutput | Format-Table
    }
}

# TBD
function Disable-PIMGroup {

}