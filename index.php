<?

//include the class
//remember the configuration file is located in:
//proxyConfiguration.ini

include("./proxyConnector.class.php");

//get an istance of the proxy
$connection = proxyConnector::getIstance();

//connect to google.com and change my identity
//because "switchIdentityAfterRequest" is set to TRUE
//in the .ini file
$connection->launch("http://www.google.com/", null);

//get the data  and show it
$data = $connection->getProxyData();

echo "<pre>";
print_r($data);