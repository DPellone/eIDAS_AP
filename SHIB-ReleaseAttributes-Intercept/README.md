# EidasReleaseAttributes

## Descrizione
EidasRealeaseAttributes � un'estensione per il software Shibboleth IdP che consiste in un flusso Spring da inserire come interceptor all'interno del profilo di autenticazione SAML2 SSO.  Il suo scopo � quello di aggiungere alla lista di attributi da rilasciare ad un eIDAS-Service tutti quelli presenti all'interno della richiesta: in particolare, dall'elemento `Extensions` viene estratto, se presente, l'elemento `RequestedAttributes`, il quale dovr� contenere la lista di attributi richiesti come elementi `RequestedAttribute`.

## Compilazione
Il software viene fornito come progetto Java gestito tramite [Maven](https://maven.apache.org/): per ottenere il pacchetto JAR � sufficiente portarsi nella cartella del progetto ed eseguire da riga di comando

    mvn package

## Installazione
Per installare il plugin in Shibboleth IdP, copiare il file JAR generato nel passo precedente all'interno della cartella *edit-webapp* nella directory di installazione di Shibboleth (*{idp.home}*), poi ricompilare l'IdP e ridistribuirlo sull'application server.  Per poter usare l'interceptor � necessario copiare il contenuto della cartella *intercept* all'interno della directory *{idp.home}/flows/intercept*; al termine dell'operazione verr� aggiunta una sottocartella denominata *eidasReleaseAttributes* che conterr� due file: uno contiene la definizione del bean Spring costituito dalla classe che esegue il confronto, mentre l'altro descrive il flusso Spring da eseguire all'attivazione dell'intercept.  Aggiungere poi la seguente riga all'elemento `list` del file *{idp.home}/conf/intercept/profile-intercept.xml*:

    <bean id="intercept/eidasReleaseAttributes" parent="shibboleth.InterceptFlow" />

� possibile abilitare l'interceptor aggiungendolo tra i `postAuthenticationFlows` di un flusso di autenticazione SAML2.SSO nel file *{idp.home}/conf/relying-party.xml*; per maggiori informazioni sugli interceptor e il loro funzionamento, consultare la documentazione del software Shibboleth disponibile [qui](https://wiki.shibboleth.net/confluence/display/IDP30/ProfileInterceptConfiguration).