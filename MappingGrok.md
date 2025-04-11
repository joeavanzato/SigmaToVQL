This document attempts to plainly lay out the 'default' artifact mappings provided in SigmaToVQL to help analysts write rules against them easily and proficiently.

This attempts to breakout the following:
* What artifacts have a map
* What 'log source' they map to
* What fields they translate to

This knowledge can then be applied directly in Sigma rules for hunting without touching VQL.

The document is structed as follows:

* **product1**
  * **category1**
    * **service1**
      * Artifact 1 Mapped Fields of Interest
      * Artifact 2 ...
    * **service2**
      * Artifact 1 ...
  * **category2**
    * **service1**
      * Artifact 1 ...

In this way, it is possible to quickly ascertain which artifacts are mapped under which categories along with relevant metadata.

Mapped fields simply represent a normalization of data to field-names commonly associated with the category/product/service, if any are available.  The default Velociraptor columns can still be used regardless, even if the same column is mapped to 1 or more other aliases.

* **windows**
  * **file_access**
      * **amcache**
        * Windows.System.Amcache (InventoryApplicationFile)
          * Image
          * TargetFilename
  * **network_connection**
      * **hostsfile**
        * Windows.System.HostsFile
          * Resolution
          * Hostname
          * DestinationHostname
  * **image_load**
      * **dlls**
        * Windows.System.DLLs
          * ImageLoaded
          * Image
  * **dns_query**
      * **dnscache**
        * Windows.System.DNSCache
          * Fields:
            * QueryName
            * DestinationHostname
  * **ps_module**
  * **ps_script**
  * **process_creation**
  * **driver_load**
      * **runningdrivers**
        * Windows.Sys.Drivers (RunningDrivers)
          * Fields:
            * ImageLoaded
* 