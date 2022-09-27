/*
Copyright (C) ws-fed proxy  Armin Felder

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

var fm = {
  'nameIdentifier': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  'name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  'givenname': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  'surname': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  'upn': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
  'groups': 'http://schemas.xmlsoap.org/claims/Group',
  'sid': "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
};

/**
 *
 * Passport User Profile Mapper
 *
 * A class to map passport.js user profile to a wsfed claims based identity.
 *
 * Passport Profile:
 * http://passportjs.org/guide/profile/
 *
 * Claim Types:
 * http://msdn.microsoft.com/en-us/library/microsoft.identitymodel.claims.claimtypes_members.aspx
 *
 * @param  {Object} pu Passport.js user profile
 */
function OWAProfileMapper (pu) {
  if(!(this instanceof OWAProfileMapper)) {
    return new OWAProfileMapper(pu);
  }
  this._pu = pu;
}

/**
 * map passport.js user profile to a wsfed claims based identity.
 *
 * @return {Object}    WsFederation claim identity
 */
OWAProfileMapper.prototype.getClaims = function () {
  const claims = {};

  claims[fm.nameIdentifier]  = this._pu.id;
  claims[fm.upn] = this._pu.upn;
  claims[fm.sid] = this._pu.sid;

  return claims;
};

/**
 * returns the nameidentifier for the saml token.
 *
 * @return {Object} object containing a nameIdentifier property and optional nameIdentifierFormat.
 */
OWAProfileMapper.prototype.getNameIdentifier = function () {
  var claims = this.getClaims();

  return {
    nameIdentifier: claims[fm.nameIdentifier]
  };

};

/**
 * claims metadata used in the metadata endpoint.
 *
 * @param  {Object} pu Passport.js profile
 * @return {[type]}    WsFederation claim identity
 */
OWAProfileMapper.prototype.metadata = [ {
  id: "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
  optional: false,
  displayName: "Primary SID",
  description: "The primary SID of the user"
}, {
  id: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
  optional: false,
  displayName: "UPN",
  description: "The user principal name (UPN) of the user"
}];

module.exports = OWAProfileMapper;
