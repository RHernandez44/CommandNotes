#### Structured Threat Information eXpression (STIX)
A language designed for standard expression of threat information, developed by MITRE and maintained by the OASIS CTI Technical Committee. STIX allows standard expression of observed or recorded events, associated threat actors, adversary techniques, and defensive actions. For example, a STIX construct can represent an indicator of a potential future threat or a past incident that needs additional response or analysis.
#### Trusted Automated eXchange of Indicator Information (TAXII)
An application-layer protocol designed for exchanging STIX-based information over HTTPS; the CTI TC maintains it along with STIX. TAXII allows secure relationships for organizations to distribute threat information from a central clearinghouse, subscribe to a central source, or exchange information with peers.
#### OpenIOC
An extensible XML schema for describing IoCs. It allows you to express an IOC in a standard, machine-readable format, containing a wide variety of criteria such as files, URLs, processes, network connections, and so on. While OpenIOC is not a required AIS standard, it is a popular tool for creating or editing indicators. Once you do so, you can convert them to STIX format and share them using TAXII.

#### Cyber Observable eXpression (CyBOX) 
A framework developed by Mitre, which is similar in purpose to OpenIOC. It describes a broader range of observable events by default but was designed with extensions to allow OpenIOC entries. CyBOX is integrated into STIX as of version 2.0.