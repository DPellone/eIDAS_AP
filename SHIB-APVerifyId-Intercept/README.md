# APVerifyId

## Descrizione
APVerifyId è un'estensione per il software Shibboleth IdP che consiste in un flusso Spring da inserire come interceptor all'interno del profilo di autenticazione SAML2 SSO.  Il suo scopo è quello di verificare la corrispondenza tra il nome utente presente nella richiesta pervenuta con quello recuperato per mezzo del flusso di autenticazione `External` o `RemoteUser`. Il nome utente da estrarre dalla richiesta viene ricercato nell'elemento `Subject`, se presente.

## Compilazione
Il software viene fornito come progetto Java gestito tramite [Maven](https://maven.apache.org/): per ottenere il pacchetto JAR è sufficiente portarsi nella cartella del progetto ed eseguire da riga di comando

    mvn package

## Installazione
Per installare il plugin in Shibboleth IdP, copiare il file JAR generato nel passo precedente all'interno della cartella *edit-webapp* nella directory di installazione di Shibboleth (*{idp.home}*), poi ricompilare l'IdP e ridistribuirlo sull'application server.  Per poter usare l'interceptor è necessario copiare il contenuto della cartella *intercept* all'interno della directory *{idp.home}/flows/intercept*; al termine dell'operazione verrà aggiunta una sottocartella denominata *APVerifyId* che conterrà due file: uno contiene la definizione del bean Spring costituito dalla classe che esegue il confronto, mentre l'altro descrive il flusso Spring da eseguire all'attivazione dell'intercept.  Aggiungere poi la seguente riga all'elemento `list` del file *{idp.home}/conf/intercept/profile-intercept.xml*:

    <bean id="intercept/APVerifyId" parent="shibboleth.InterceptFlow" />

È possibile abilitare l'interceptor aggiungendolo tra i `postAuthenticationFlows` di un flusso di autenticazione SAML2.SSO nel file *{idp.home}/conf/relying-party.xml*; per maggiori informazioni sugli interceptor e il loro funzionamento, consultare la documentazione del software Shibboleth disponibile [qui](https://wiki.shibboleth.net/confluence/display/IDP30/ProfileInterceptConfiguration).