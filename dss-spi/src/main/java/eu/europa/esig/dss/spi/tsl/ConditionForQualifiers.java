/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.List;

/**
 * This class is a DTO representation for qualifier and conditions
 *
 */
public class ConditionForQualifiers implements Serializable {

	private static final long serialVersionUID = 6284808669027768365L;

	/** The condition */
	private final Condition condition;

	/** List of Qualifiers */
	private final List<String> qualifiers;

	/** Whether the corresponding Qualifications extension is marked as critical */
	private final boolean critical;

	/**
	 * Default constructor for a non-critical condition
	 *
	 * @param condition {@link Condition}
	 * @param qualifiers a list of {@link String}
	 */
	public ConditionForQualifiers(final Condition condition, final List<String> qualifiers) {
		this(condition, qualifiers, false);
	}

	/**
	 * Constructor with criticality level defined
	 *
	 * @param condition {@link Condition}
	 * @param qualifiers a list of {@link String}
	 * @param critical whether the Qualifications extension is critical
	 */
	public ConditionForQualifiers(final Condition condition, final List<String> qualifiers, final boolean critical) {
		this.condition = condition;
		this.qualifiers = qualifiers;
		this.critical = critical;
	}

	/**
	 * Gets the list of qualifiers
	 *
	 * @return a list of {@link String}
	 */
	public List<String> getQualifiers() {
		return qualifiers;
	}

	/**
	 * Gets the condition
	 *
	 * @return {@link Condition}
	 */
	public Condition getCondition() {
		return condition;
	}

	/**
	 * Gets whether the corresponding Qualifications extension is marked as critical
	 *
	 * @return TRUE if the condition is critical, FALSE otherwise
	 */
	public boolean isCritical() {
		return critical;
	}

	@Override
	public String toString() {
		return "ConditionForQualifiers [qualifiers=" + qualifiers + ", condition=" + condition + ", critical=" + critical + "]";
	}

}
