function Enable-PIMRole {
    param(
        [Parameter(Mandatory=$false)]
        [Alias("SkipReason")]
        [switch]$SkipJustification,

        [Parameter(Mandatory=$false)]
        [Alias("Reason")]
        [string]$Justification,

        [Parameter(Mandatory=$false)]
        [string]$TicketingSystem
    )

    <#
    .DESCRIPTION
    Enable Entra ID PIM roles via an easy to use TUI (Text User Interface). Only supports enabling; not disabling.

    .PARAMETER SkipJustification
    Optional. If specified, it sets the reason/ justifaction for activation to be "xxx".

    .PARAMETER Justification
    Optional. If specified, it sets the reason/ justifaction for activation to whatever is input.

    .PARAMETER TicketingSystem
    Optional. If specified, it sets the tickting system (for role activations that need a ticket number) to be whatever is input.
    #>

    begin {
        $requiredScopesArray = "RoleEligibilitySchedule.Read.Directory","RoleEligibilitySchedule.ReadWrite.Directory","RoleManagement.Read.Directory","RoleManagement.Read.All","RoleAssignmentSchedule.ReadWrite.Directory","RoleManagement.ReadWrite.Directory","RoleAssignmentSchedule.Remove.Directory"

        try {
            Connect-MgGraph -Scopes $requiredScopesArray -NoWelcome -ErrorAction Stop

        } catch {
            throw "$($_.Exception.Message)"
        }

        $context = Get-MgContext

        $scopes = $context.scopes

        if ($scopes -notcontains "Directory.ReadWrite.All") {
            foreach ($requiredScope in $requiredScopesArray) {
                if ($requiredScope -notin $scopes) {
                    Write-Warning "Required scope '$requiredScope' missing"
                }
            }
        }

        $userId = (Get-MgUser -UserId $context.Account).Id

        try {
            Write-Progress -Activity "Fetching all eligibile Entra ID roles"
            [array]$myEligibleRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$userId'" -ErrorAction Stop

            Write-Progress -Activity "Fetching all active Entra ID roles"
            [array]$myActiveRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ExpandProperty RoleDefinition -All -Filter "principalId eq '$userId'" -ErrorAction Stop
            
        } catch {
            throw "Error fetching roles: $($_.Exception.Message)"
        }

        # Create a cache of assignments. This is faster as I can lookup a bunch of them beforehand.
        $policyAssignmentHash = @{}
        # I must set scopeId to '/' coz if I search for a specific scopeId it errors: Attempted to perform an unauthorized operation.
        $searchSnippetMain = "scopeType eq 'DirectoryRole' and scopeId eq '/' and ("
        $searchSnippetsArray = @()

        # Filter has a max length (not sure what) so I will do it in batches of 5. 
        # A temp variable I keep incrementing
        $counter = 0
        # Total number of entries for this scope
        $totalCount = $myEligibleRoles.Count

        # Loop through the entries
        foreach ($roleObj in $myEligibleRoles) {
            Write-Progress -Activity "Fetching policies assigned to roles" -Id 0
            $counter++
            $roleDefinitionId = $roleObj.RoleDefinitionId

            # An array where I keep adding the snippets
            $searchSnippetsArray += "roleDefinitionId eq '$roleDefinitionId'"

            # In batches of 5, or if the counter has reached the end...
            if ($counter % 5 -eq 0 -or $counter -ge $totalCount) {
                # ... construct the search snippet
                $searchSnippet = $searchSnippetMain + $($searchSnippetsArray -join ' or ') + ")"

                # Do the search
                Write-Progress -Activity "Fetching..." -ParentId 0 -Id 1 -Status "${counter}/${totalCount}" -PercentComplete $($counter*100/$totalCount)
                try {
                    $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter $searchSnippet -ExpandProperty "policy(`$expand=rules)" -ErrorAction Stop
                
                } catch {
                    throw "Error fetching policy assignments: $($_.Exception.Message)"
                }
                
                # And add it to the hash
                foreach ($result in $policyAssignment) {
                    $policyAssignmentHash[$($result.RoleDefinitionId)] = $result
                }

                # Initialize the array again
                $searchSnippetsArray = @()
            }
        }

        # I tried to do the same for policies & rules, but couldn't get it working... I can't seem to filter on PolicyId or policyId or any other variants!

        Write-Progress -Id 1 -Completed
        Write-Progress -Id 0 -Completed
    }

    process {
        # Cache the policy expiration rules so I don't have to lookup each time. 
        # I don't think this is really needed coz in my testing there seems to be a separate policy per role, but no harm done I suppose... useful when troubleshooting!
        $policyExpRulesCache = @{}
        $policyEnablementRulesCache = @{}
        $roleDefinitionsCache = @{}

        # I use these for showing progress
        [int]$counter = 0
        [int]$totalCount = $myEligibleRoles.Count

        [array]$myActiveRoleIds = $myActiveRoles.RoleDefinitionId

        $roleStates = foreach ($roleObj in $myEligibleRoles) {
            $counter++
            $percentageComplete = ($counter/$totalCount)*100

            $roleDefinitionId = $roleObj.RoleDefinitionId
            $roleName = $roleObj.RoleDefinition.DisplayName

            $roleDefinitionsCache[$roleDefinitionId] = $roleName

            $timespanArray = @()
            $roleExpired = $false
            $roleAssignmentType = "Not Active"

            Write-Progress -Activity "Processing role '$roleName'" -Id 2 -PercentComplete $percentageComplete -Status "$counter/$totalCount"

            if ($roleDefinitionId -in $myActiveRoleIds) {
                $activeRoleObj = $myActiveRoles | Where-Object { $_.RoleDefinitionId -eq "$roleDefinitionId" }
                
                # Double checking coz during my testing I ran into instances where this was sometimes incomplete
                if ($activeRoleObj.ScheduleInfo.Expiration.EndDateTime) {
                    $roleAssignmentType = $activeRoleObj.AssignmentType

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


            } else {
                $roleExpired = $true
            }

            # Using the roledefinitionid, find the policy assignment on this role
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyassignment?view=graph-rest-1.0
            
            <#
            $roleDirectoryScopeId = $roleObj.DirectoryScopeId
            
            Write-Progress -Activity "Fetching policy assignment of role '$roleName'" -Id 2 -PercentComplete $percentageComplete -Status "$counter/$totalCount"
            try {
                $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '$roleDirectoryScopeId' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleDefinitionId'" -ErrorAction Stop

            } catch {
                Write-Warning "Error fetching policy assignments for '$roleName': $($_.Exception.Message)"
                continue
            }
            #>
            # Skipping the above code as I now cache it before hand. This is faster than doing individual lookups.
            $policyAssignment = $policyAssignmentHash[$roleDefinitionId]

            # From there find the policy :)
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicy?view=graph-rest-1.0
            $policyId = $policyAssignment.PolicyId

            Write-Progress -Activity "Fetching policy id '$(($policyId -split '_')[2])'" -ParentId 2 -Id 3
            try {
                $policyObj = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $policyId -ExpandProperty Rules -ErrorAction Stop

            } catch {
                Write-Warning "Error fetching policy id '$policyId': $($_.Exception.Message)"
                continue
            }
            
            # The policy is what defines the max duration of the role and other factors. We are interested in here are the rules
            # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule?view=graph-rest-1.0
            # If I have the rule already cached, use that
            if ($policyExpRulesCache.Keys -contains $policyId) {
                $expirationRule = $policyExpRulesCache.$policyId

            } else {
                # The 'Expiration_EndUser_Assignment' rule in the policy is what defines the maximum duration
                # https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0
                $expirationRule = ($policyObj.Rules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }).AdditionalProperties
                $policyExpRulesCache.$policyId = $expirationRule
            }

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

                # Just in case there's a delay between getting the states and when I calculate this...
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
                $policyEnablementRulesCache.$policyId = $expirationRule
            }

            Write-Progress -Completed -Id 3

            [pscustomobject][ordered]@{
                "RoleName" = $roleName
                "Status" = $roleAssignmentType
                "ExpiresIn" = if (!($roleExpired)) { $timespanArray -join ' ' }
                "MaxDuration" = $maxDuration
                "EnablementRules" = $enablementRule -join '|' -replace 'Justification','Reason' -replace 'Ticketing','Ticket' -replace 'MultiFactorAuthentication','MFA'
                "More" = [pscustomobject]@{
                    "RoleDefinitionId" = $roleObj.RoleDefinitionId
                    "DirectoryScopeId" = $roleObj.DirectoryScopeId
                    "MaxDuration" = $expirationRule.maximumDuration
                    "EnablementRule" = $enablementRule
                }
            }
        }

        Write-Progress -Completed -Id 2

        $userSelections = $roleStates | Out-ConsoleGridView

        # Lets ask for the required info upfront
        $justificationsHash = @{}
        $ticketSystemHash = @{}
        $ticketNumberHash = @{}

        foreach ($selection in $userSelections) {
            if ($selection.Status -eq "Not Active") {
                if ($selection.More.EnablementRule -contains "Justification") {
                    Write-Host -NoNewline -ForegroundColor Yellow "'$($selection.RoleName)' "

                    if ($SkipJustification) {
                        $justificationsHash[$($selection.RoleName)] = "xxx"
                        Write-Host "Reason will be set to: xxx"

                    } elseif ($Justification.Length -ne 0) {
                        $justificationsHash[$($selection.RoleName)] = $Justification
                        Write-Host "Reason will be set to: $Justification"

                    } else {
                        
                        $justificationInput = Read-Host "Please provide a reason"
                        
                        # If the justitication ends with an asterisk, use it for everything else that follows...
                        if ($justificationInput -match '\*$') {
                            $justificationInput = $justificationInput -replace '\*$',''
                            $Justification = $justificationInput
                        }

                        $justificationsHash[$($selection.RoleName)] = $justificationInput
                    }
                }

                if ($selection.More.EnablementRule -contains "Ticketing") {
                    Write-Host -NoNewline -ForegroundColor Yellow "'$($selection.RoleName)' "

                    $ticketNumberHash[$($selection.RoleName)] = Read-Host "Please provide a ticket number"

                    if ($TicketingSystem.Length -ne 0) {
                        Write-Host -NoNewline -ForegroundColor Yellow "'$($selection.RoleName)' "
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
        }

        $requestObjsArray = @()
        foreach ($selection in $userSelections) {
            Write-Host -NoNewline -ForegroundColor Yellow "'$($selection.RoleName)' "

            if ($selection.Status -ne "Not Active") {
                Write-Host "Skipping as its status is '$($selection.Status)'"

            } else {
                Write-Host "Enabling for $($selection.MaxDuration)"

                $params = @{
                    Action = "selfActivate"
                    PrincipalId = $userId
                    RoleDefinitionId = $selection.More.RoleDefinitionId
                    DirectoryScopeId = $selection.More.DirectoryScopeId

                    ScheduleInfo = @{
                        StartDateTime = Get-Date
                        Expiration = @{
                            Type = "AfterDuration"
                            Duration = $selection.More.MaxDuration
                        }
                    }
                }

                if ($selection.More.EnablementRule -contains "Justification") {
                    $params.Justification = $justificationsHash[$($selection.RoleName)]
                }

                if ($selection.More.EnablementRule -contains "Ticketing") {
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
        }

        if ($userSelections.Count -ne 0) {
            $counter = 0
            $maxWaitSecs = 20
            while ($counter -lt $maxWaitSecs) {
                Write-Progress "Waiting $maxWaitSecs seconds before showing the final status" -PercentComplete $($counter*100/$maxWaitSecs) -Status " "
                Start-Sleep -Seconds 1
                $counter++
            }
        }

        $finalOutput = foreach ($requestObj in $requestObjsArray) {
            Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -UnifiedRoleAssignmentScheduleRequestId $requestObj.Id | Select-Object -Property @{
                "Name" = "Role";
                "Expression" = { $roleDefinitionsCache[$($_.RoleDefinitionId)] }
            },Status 
        }

        $finalOutput | Format-Table
    }
}