package eu.eidas.node.specificcommunication;

import java.math.BigDecimal;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableSet;

import eu.eidas.auth.commons.attribute.AttributeDefinition;
import eu.eidas.auth.commons.attribute.ImmutableAttributeMap;


// --- MOD ---
/**
 * Classe astratta che fornisce i metodi per costruire l'identificativo di un utente presso un certo AP
 * @author Daniele Pellone
 *
 */
public abstract class IDBuilder {
	
	/**
	 * Costruisce il nome utente a partire dagli attributi e dai token di un certo AP
	 * @param syntax Lista di token che rappresentano la modalità con cui costruire l'ID
	 * @param attributes Lista di attributi dell'utente
	 * @return
	 */
	public static String getID(List<StringToken> syntax, ImmutableAttributeMap attributes) {
		String id = "";
		for (StringToken stringToken : syntax) {
			//Se il token è una stringa semplice, questa viene aggiunta direttamente
			if(!stringToken.getIsAttribute()){
				id += stringToken.getString();
				continue;
			}
			// Alla ricerca dell'attributo corretto
			ImmutableSet<AttributeDefinition<?>> attributesSet = attributes.getDefinitionsByFriendlyName(stringToken.getString());
			for (AttributeDefinition<?> attributeDefinition : attributesSet) {
				if(attributeDefinition.getParameterizedType() == String.class){
					String s = attributes.getFirstValue((AttributeDefinition<String>)attributeDefinition);
					id += applyModifiers(s, stringToken);
					break;
				}
			}
			
		}
		return id;
	}
	
	private static String applyModifiers(String string, StringToken token){
		String newString = new String(string);
		if(token.getCharacters() != null)
			newString = string.substring(0, token.getCharacters().intValue());
		switch (token.getUpperOrLower()) {
		case "AllUpper":
			newString = newString.toUpperCase(Locale.ROOT);
			break;
		case "AllLower":
			newString = newString.toLowerCase(Locale.ROOT);
		default:
			break;
		}
		return newString;
	}
	
}
