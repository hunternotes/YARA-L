rule AgentTesla {
  meta:
    version = "0.01"
    created =  "2022-01-27"
    description = "Scheduled task creation by AgentTesla"
    reference = "https://tria.ge/220120-zzenqsbfem/behavioral2, https://app.any.run/tasks/4aaf4793-1074-4ab8-aab2-230e5cacc325/"
    tags= "T1053"
    logsource = "EDR"

  events:
    // Parent process full path contains %TEMP%
    $e.principal.process.file.full_path = /appdata\\local\\temp/ nocase and
    $e.target.process.file.full_path = /schtasks\.exe/ and
    (
        $e.target.process.command_line = /\/create/ nocase and
        // schedule xml file is also in %TEMP%
        $e.target.process.command_line = /appdata\\local\\temp/ nocase
    )

  condition:
    $event

}