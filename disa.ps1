<#
.SYNOPSIS

This script has been created specifically to consume the DISA STIG for Suse Linux.  Should probably work fine on other STIGs as well
.DESCRIPTION

This script has been created specifically to consume the DISA STIG for Suse Linux.  Should probably work fine on other STIGs as well.  This script will allow you to view the XML contents using Powershell objects
.PARAMETER xmlfile

This parameter will be used to search for the article that you specify.  Required unless -listarticles is specified.
.PARAMETER listarticles

List all of the articles in a summary view.  Can be used with -search_id to narrow a search
.PARAMETER search_id

Can be either the full ID of the article or a partial, for use with listarticles
.PARAMETER check

Shows only the check info for the article
.PARAMETER fix

Shows only the fix info for the article
.EXAMPLE

./disa.ps1 -listarticles
.EXAMPLE

./disa.ps1 -search_id 44877
#>

# Need to set some type of default and then error based on that instead of
# throwing an exception if no input is provided.  Maybe could list by default?
Param(
    [string]$xmlfile,
    [switch]$listarticles,
    [string]$search_id,
    [switch]$fix,
    [switch]$check
)

# Figure out which xml file to use and then return the file as an object
function Get-DISAFile {
    $folder_xml_files = get-childitem .   | where-object {$_.name -like '*.xml'}
    $well_named_xml   = $folder_xml_files | where-object {$_.name -like '*STIG*'}

    if ($xmlfile) {
        if (test-path $xmlfile) {
            return (get-item $xmlfile)
        } else {
            throw "Specified file does not exist. Please check the name and try again."
        }
    } elseif ( $folder_xml_files.count -eq 1 ) {
        return $folder_xml_files[0]
    } elseif  ( $well_named_xml.count -eq 1 ) {
        return $well_named_xml[0]  
    } else {
        throw "Several choices found in current working directory. Please specify by using the -xmlfile parameter"
    }
}

# function to provide a summary-style list of objects
function List-DISA {
    $disa_items = @()
    foreach ($search_id in $xml_file_contents.Benchmark.group.rule) {
      $article_description = $search_id.description.Replace("<VulnDiscussion>","")
      $vuln_tag_location = $article_description.indexof('</VulnDiscussion>')
      $article_description = $article_description.Substring(0,$vuln_tag_location)
      # remove that revision string at the end
      $article_id = $search_id.id.replace("r1_rule","")
      $article_id = $article_id.replace("r2_rule","")
      $article_id = $article_id.replace("r3_rule","")
      $current_item = New-Object -TypeName PSObject
      $current_item | Add-Member -MemberType NoteProperty -Name 'id' -Value $article_id
      $current_item | Add-Member -MemberType NoteProperty -Name 'title' -Value $search_id.title
      $current_item | Add-Member -MemberType NoteProperty -Name 'description' -Value $article_description
      $disa_items += $current_item
    }
      return $disa_items
}

function Fix-Text {
    $complete_text = ($xml_file_contents.Benchmark.group.rule | where-object {$_.id -like "*$search_id*"}).fixtext."#text"
    $cmd_pos = $complete_text.indexof('#')
    $fix_command = $complete_text.substring($cmd_pos)
    write-host $fix_command
    $fix_obj = New-Object -TypeName psobject
    $fix_obj | Add-Member -MemberType NoteProperty -Name 'fix_text' -Value $complete_text
    $fix_obj | Add-Member -MemberType NoteProperty -Name 'Command' -Value $fix_command
    return $fix_obj
}

# gets a more detailed view of a single item
function Get-Article {
    if ($search_id) {
        $current_item = $xml_file_contents.Benchmark.group.rule | select id,version,title,description,name,namespaceuri,fixtext,check | where-object {$_.id -like "*$search_id*"}
        if ($current_item.count -gt 1) {throw "More than one item found.  Please use complete article number rather than partial"}
        $article_result = New-Object -TypeName psobject
        $article_id = $current_item.id.replace("r1_rule","")
        $article_result | Add-Member -MemberType NoteProperty -Name 'id' -Value $article_id
        $article_result | Add-Member -MemberType NoteProperty -Name 'title' -Value $current_item.title
        $article_description = $current_item.description.Replace("<VulnDiscussion>","")
        $vuln_tag_location = $article_description.indexof("</VulnDiscussion>")
        $article_description = $article_description.Substring(0,$vuln_tag_location)
        $article_result | Add-Member -MemberType NoteProperty -Name 'description' -Value $article_description
        $article_result | Add-Member -MemberType NoteProperty -Name 'version' -value $current_item.version
        $article_result | Add-Member -MemberType NoteProperty -Name 'name' -value $current_item.name
        $article_result | Add-Member -MemberType NoteProperty -Name 'namespaceuri' -value $current_item.namespaceuri
        $article_result | Add-Member -MemberType NoteProperty -Name 'fixtext' -value $current_item.fixtext.'#text'
        $article_result | Add-Member -MemberType NoteProperty -Name 'check' -value $current_item.check.'check-content'
    } else {
        get-help ./disa.ps1
    }
    return $article_result
}

# Get and store the file path
$xml_file = Get-DISAFile
# Consume the contents of the file as xml
[xml]$xml_file_contents = get-content $xml_file

# If -listarticles is used provide a summary view of the search
if ( $PSBoundParameters.ContainsKey('listarticles')) {
    List-DISA
} elseif ($PSBoundParameters.ContainsKey('check')) {
    (Get-Article).check
} elseif ($PSBoundParameters.ContainsKey('fix')) {
    (Get-Article).fixtext
} else {
    Get-Article
}
