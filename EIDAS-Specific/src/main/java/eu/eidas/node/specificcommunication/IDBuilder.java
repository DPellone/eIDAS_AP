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
public class IDBuilder {
	
	private ImmutableAttributeMap attributes;
	private List<StringToken> syntax;
	
	public IDBuilder(List<StringToken> syntax, ImmutableAttributeMap attributes){
		this.syntax = syntax;
		this.attributes = attributes;
	}
	
	public String getID() {
		String id = "";
		for (StringToken stringToken : syntax) {
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
	
	private String applyModifiers(String string, StringToken token){
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
