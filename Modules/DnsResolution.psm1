# DnsResolution.psm1 — passive DNS lookups

function Resolve-ETMDnsRecords {
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [string[]]$RecordTypes = @('A', 'AAAA', 'CNAME', 'MX', 'TXT')
    )
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($type in $RecordTypes) {
        try {
            $records = Resolve-DnsName -Name $Hostname -Type $type -ErrorAction Stop
            foreach ($r in $records) {
                $results.Add([pscustomobject]@{
                    hostname   = $Hostname
                    recordType = $type
                    value      = if ($r.IPAddress) { $r.IPAddress } elseif ($r.NameHost) { $r.NameHost } else { $r.Strings -join ' ' }
                })
            }
        } catch { }
    }
    return $results.ToArray()
}

Export-ModuleMember -Function 'Resolve-ETMDnsRecords'
