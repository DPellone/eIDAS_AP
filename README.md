# eIDAS Node
Questo progetto consiste in un nodo eIDAS completo con supporto per un Attribute Provider che usi il profilo SAML2 Web Browser SSO, inoltre sono presenti due plugin per tale AP, se realizzato con software [Shibboleth](https://www.shibboleth.net/), che consentono di rilasciare gli attributi richiesti ([SHIB-ReleaseAttributes-Intercept](https://github.com/DPellone/eIDAS-Node/tree/master/SHIB-ReleaseAttributes-Intercept)) e verificare la corrispondenza tra il nome utente richiesto e quello verificato tramite IdP ([SHIB-APVerifyId-Intercept](https://github.com/DPellone/eIDAS-Node/tree/master/SHIB-APVerifyId-Intercept)); maggiori informazioni su questi ultimi nel file README all'interno delle directory.

## Descrizione
Il codice qui presente è basato interamente sulla versione 1.4 del nodo eIDAS fornito dalla rete di cooperazione europea (la versione più recente può essere ottenuta [qui](https://ec.europa.eu/cefdigital/wiki/display/CEFDIGITAL/eIDAS-Node+-+Current+release)).  Sono state apportate modifiche e aggiunte per consentire al nodo di integrare gli attributi ricevuti dal sistema di identità digitale con altri ottenuti tramite interrogazione di un AP.  Compilazione, installazione e configurazione avvengono secondo quanto indicato nella guida fornita insieme al software (presente nel file eIDAS\_Node\_Guide.pdf).  Oltre alla configurazione indicata nella guida, al file di configurazione `eidas.xml` devono essere aggiunte le seguenti proprietà:
* `webservice.listURL`: URL da contattare per recuperare la lista di AP;
* `webservice.mappingURL`: URL da contattare per recuperare le informazioni su un particolare AP;
* `webservice.keystore`: percorso del keystore contenete la chiave privata e il certificato da usare per l’autenticazione client TLS nei confronti del WebService, insieme con il certificato del WebService stesso;
* `webservice.keystore.passw`: password del keystore.

## Modifiche apportate
##### presentConsent.jsp
* Percorso: EIDAS\EIDAS-Node\src\main\webapp\
* Modifica

Questo file contiene la pagina visualizzata all'utente per richiedergli il consenso al rilascio degli attributi opzionali.  È stata modificata per aggiungere un menu per selezionare l'AP da cui eventualmente recuperare gli attributi mancanti.

##### ColleagueRequestServlet.java
* Percorso: EIDAS-Node\src\main\java\eu\eidas\node\service\
* Modifica

Servlet che gestisce la richiesta HTTP dell'utente dopo che questi ha prestato il consenso al rilascio degli attributi.  È stato aggiunto il metodo *getAttributeProviderList* che consente di recuperare la lista degli AP disponibili, per poi visualizzarla all'utente.

##### apRedirect.jsp
* Percorso: EIDAS\EIDAS-Node\src\main\webapp\internal\
* Aggiunta

Pagina jsp creata a partire dal file "idpRedirect.jsp" per consentire all'utente di essere rediretto verso l'AP prescelto per trasportare la richiesta SAML.

##### IdPResponseServlet.java
* Percorso: EIDAS-Node\src\main\java\eu\eidas\node\service\
* Modifica

Servlet che gestisce la richiesta HTTP dell'utente dopo che questi ha ottenuto la risposta da un IdP o un AP.  Il metodo che viene invocato per eseguire l'elaborazione della richiesta è stato modificato in modo che tenga conto del risultato di tale elaborazione: se esso è `null`, l'utente viene inoltrato sulla pagina "apRedirect.jsp", in quanto questo valore indica che la risposta da inviare all'eIDAS-Connector non è ancora pronta.

##### SpecificEidasService.java
* Percorso: EIDAS\EIDAS-Specific\src\main\java\eu\eidas\node\auth\specific\
* Modifica

In questa classe, che fornisce i metodi per elaborare le richieste e le risposte secondo il protocollo del sistema di identità digitale dello specifico Paese, è stato inserito il metodo *createSamlAuthNRequest*, il cui scopo è costruire la richiesta da inviare ad un AP.  Utilizzando i metodi forniti dalla libreria OpenSAML, vengono recuperati i Metadati dell'AP e, in seguito, creata la richiesta con le informazioni fornite alla funzione.  Viene restituito un array di byte che contiene la richiesta firmata da inviare codificata in Base64.

##### IDBuilder.java
* Percorso: EIDAS\EIDAS-Specific\src\main\java\eu\eidas\node\specificcommunication\
* Aggiunta

Classe astratta che fornisce i metodi per costruire l'identificativo di un utente presso un certo AP.  Il metodo `getID` consente, a partire dalla lista di attributi di un utente e da quella dei token recuperati dal WebService, di generare il nome utente da usare per interrogare l'AP.

##### StringToken.java
* Percorso: EIDAS\EIDAS-Specific\src\main\java\eu\eidas\node\specificcommunication\
* Aggiunta

Classe che rappresenta un token per la costruzione del nome utente presso un AP e che viene usata per effettuare il parsing delle risposte in formato JSON del WebService.

##### SpecificProxyServiceImpl.java
* Percorso: EIDAS\EIDAS-Specific\src\main\java\eu\eidas\node\specificcommunication\
* Modifica

Questa classe si occupa della creazione della richiesta per l'IdP e della gestione della sua risposta.  Il metodo `sendRequest` è stato modificato per memorizzare in una lista apposita la corrispondenza tra richiesta e AP da contattare se dovessero mancare degli attributi nella risposta.  Nel metodo `processResponse` è stato aggiunto il codice per gestire il caso in cui la risposta non dovesse contenere tutti gli attributi richiesti: in questo caso il messaggio SAML da inviare al Connector viene temporaneamente salvato e viene generata una nuova richiesta per l'AP selezionato.  Lo stesso metodo si occupa di gestire la risposta a tale richiesta, recuperando il messaggio salvato e integrandolo con i nuovi attributi.