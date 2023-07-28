/*
 * Copyright (C) 2015 Colin Mackie.
 * This software is distributed under the terms of the GNU General Public License.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace WinAuth;

[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
[MessagePackObject(keyAsPropertyName: true)]
public class GoogleAuthenticator : AuthenticatorValueDTO
{
    /// <summary>
    /// Number of digits in code
    /// </summary>
    const int CODE_DIGITS = 6;

    /// <summary>
    /// Create a new Authenticator object
    /// </summary>
    [SerializationConstructor]
    public GoogleAuthenticator() : base(CODE_DIGITS)
    {
    }

    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public override AuthenticatorPlatform Platform => AuthenticatorPlatform.Google;

    /// <summary>
    /// Number of minutes to ignore syncing if network error
    /// </summary>
    const int SYNC_ERROR_MINUTES = 5;

    /// <summary>
    /// Time of last Sync error
    /// </summary>
    static DateTime _lastSyncError = DateTime.MinValue;

    [IgnoreDataMember]
    [MPIgnore]
#if __HAVE_N_JSON__
    [N_JsonIgnore]
#endif
#if !__NOT_HAVE_S_JSON__
    [S_JsonIgnore]
#endif
    public string Serial
    {
        get
        {
            return Base32.GetInstance().Encode(SecretKey.ThrowIsNull(nameof(SecretKey)));
        }
    }

    /// <summary>
    /// Enroll the authenticator with the server.
    /// </summary>
    /// <param name="b32key"></param>
    public void Enroll(string b32key)
    {
        SecretKey = Base32.GetInstance().Decode(b32key);
        Sync();
    }

    /// <summary>
    /// Synchronise this authenticator's time with Google. We update our data record with the difference from our UTC time.
    /// </summary>
    public override void Sync()
    {
        // check if data is protected
        if (SecretKey == null && EncryptedData != null)
        {
            throw new WinAuthEncryptedSecretDataException();
        }

        // don't retry for 5 minutes
        if (_lastSyncError >= DateTime.Now.AddMinutes(0 - SYNC_ERROR_MINUTES))
        {
            return;
        }

        try
        {
            // we use the Header response field from a request to www.google.come
            using var response = AuthenticatorNetService.Google.TimeSync();

            // OK?
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new ApplicationException(string.Format("{0}: {1}", (int)response.StatusCode, response.RequestMessage));
            }

            string headerdate = response.Headers.GetValues("Date").First();
            if (string.IsNullOrEmpty(headerdate) == false)
            {
                if (DateTime.TryParse(headerdate, out var dt) == true)
                {
                    // get as ms since epoch
                    long dtms = Convert.ToInt64((dt.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalMilliseconds);

                    // get the difference between the server time and our current time
                    long serverTimeDiff = dtms - CurrentTime;

                    // update the Data object
                    ServerTimeDiff = serverTimeDiff;
                    LastServerTime = DateTime.Now.Ticks;
                }
            }

            // clear any sync error
            _lastSyncError = DateTime.MinValue;
        }
        catch (WebException)
        {
            // don't retry for a while after error
            _lastSyncError = DateTime.Now;

            // set to zero to force reset
            ServerTimeDiff = 0;
        }
    }
}
