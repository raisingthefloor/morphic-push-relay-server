// Copyright 2021 Raising the Floor - US, Inc.
//
// Licensed under the New BSD license. You may not use this file except in
// compliance with this License.
//
// You may obtain a copy of the License at
// https://github.com/raisingthefloor/morphic-push-relay-server/blob/main/LICENSE
//
// The R&D leading to these results received funding from the:
// * Rehabilitation Services Administration, US Dept. of Education under
//   grant H421A150006 (APCP)
// * National Institute on Disability, Independent Living, and
//   Rehabilitation Research (NIDILRR)
// * Administration for Independent Living & Dept. of Education under grants
//   H133E080022 (RERC-IT) and H133E130028/90RE5003-01-00 (UIITA-RERC)
// * European Union's Seventh Framework Programme (FP7/2007-2013) grant
//   agreement nos. 289016 (Cloud4all) and 610510 (Prosperity4All)
// * William and Flora Hewlett Foundation
// * Ontario Ministry of Research and Innovation
// * Canadian Foundation for Innovation
// * Adobe Foundation
// * Consumer Electronics Association Foundation

using Morphic.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Morphic.Push.Wns
{
    // NOTE: since Windows Phone has been discontinued, this implementation of WnsRelayClient does not support deleting already-pushed notifications (a Windows Phone-exclusive feature)
    public class WnsRelayClient
    {
        public enum NotificationType
        {
            [MorphicStringValue("wns/tile")]
            Tile,
            [MorphicStringValue("wns/toast")]
            Toast,
            [MorphicStringValue("wns/badge")]
            Badge,
            [MorphicStringValue("wns/raw")]
            Raw
        }

        public struct SendNotificationRequestOptions
        {
            public enum NotificationPriority
            {
                High = 1,
                Medium = 2,
                Low = 3,
                VeryLow = 4
            }

            public bool? CacheWhileClientIsOffline { set; get; }
            public NotificationPriority? Priority { set; get; }
            public bool? RequestDeviceAndConnectionStatus { set; get; }
            public string? Tag { set; get; }
            public Int64? TimeToLive { set; get; }

            // Windows Phone only
            public bool? SuppressPopup { set; get; }
            public string? Group { set; get; }
        }
        public struct SendNotificationResponseDebugHeaders
        {
            public enum DeviceConnectionStatusOption
            {
                [MorphicStringValue("connected")]
                Connected,
                [MorphicStringValue("disconnected")]
                Disconnected,
                [MorphicStringValue("tempconnected")]
                TempConnected
            }
            public enum StatusOption
            {
                [MorphicStringValue("received")]
                Received,
                [MorphicStringValue("dropped")]
                Dropped,
                [MorphicStringValue("channelthrottled")]
                ChannelThrottled
            }

            public string? XWnsDebugTrace;
            public DeviceConnectionStatusOption? XWnsDeviceConnectionStatus;
            public string? XWnsErrorDescription;
            public string? XWnsMessageId;
            public StatusOption? XWnsStatus;
            //
            public List<string>? HeaderParsingErrors;
            public void AddHeaderParsingError(string error)
            {
                if (this.HeaderParsingErrors == null)
                {
                    this.HeaderParsingErrors = new List<string>();
                }
                this.HeaderParsingErrors.Add(error);
            }
        }

        public record SendNotificationError : MorphicAssociatedValueEnum<SendNotificationError.Values>
        {
            // enum members
            public enum Values
            {
                AccessTokenIsExpired,
                AccessTokenIsInvalid,
                AccessTokenIsMismatched,
                ChannelIsExpired,
                ChannelNotFound,
                CodeHasBug,
                HttpError,
                InternalServerError,
                NetworkError,
                PayloadTooLarge,
                ServiceUnavailable,
                ThrottleLimitExceeded,
                Timeout,
            }

            // functions to create member instances
            public static SendNotificationError AccessTokenIsExpired(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.AccessTokenIsExpired) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError AccessTokenIsInvalid(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.AccessTokenIsInvalid) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError AccessTokenIsMismatched(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.AccessTokenIsMismatched) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError ChannelIsExpired(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.ChannelIsExpired) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError ChannelNotFound(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.ChannelNotFound) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError CodeHasBug(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.CodeHasBug) { ResponseDebugHeaders = responseDebugHeaders };
            // NOTE: due to the nature of WNS's response debug headers, we still return these with an HttpError _just in case_ they are populated
            public static SendNotificationError HttpError(HttpStatusCode httpStatusCode, SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.HttpError) { HttpStatusCode = httpStatusCode, ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError InternalServerError(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.InternalServerError) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError NetworkError => new SendNotificationError(Values.NetworkError);
            public static SendNotificationError PayloadTooLarge(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.PayloadTooLarge) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError ServiceUnavailable(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.ServiceUnavailable) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError ThrottleLimitExceeded(SendNotificationResponseDebugHeaders responseDebugHeaders) => new SendNotificationError(Values.ThrottleLimitExceeded) { ResponseDebugHeaders = responseDebugHeaders };
            public static SendNotificationError Timeout => new SendNotificationError(Values.Timeout);

            // associated values
            public HttpStatusCode? HttpStatusCode { get; private set; }
            // NOTE: we might be returning debug headers for all http status codes (both ones we handle and unexpected ones), as Microsoft does not provide conditions where they are NEVER supplied
            public SendNotificationResponseDebugHeaders ResponseDebugHeaders { get; internal set; }

            // verbatim required constructor implementation for MorphicAssociatedValueEnums
            private SendNotificationError(Values value) : base(value) { }
        }

        public struct SendNotificationResult
        {
            public SendNotificationResponseDebugHeaders.StatusOption? Status;
            public SendNotificationResponseDebugHeaders ResponseDebugHeaders;
        }

        public static async Task<IMorphicResult<SendNotificationResult, SendNotificationError>> SendNotificationAsync(Uri channelUri, string accessToken, NotificationType notificationType, string content, SendNotificationRequestOptions? requestOptions)
        {
            // capture our notificationType as a wnsType string
            var notificationTypeAsWnsTypeString = notificationType.ToStringValue();
            if (notificationTypeAsWnsTypeString == null)
            {
                throw new ArgumentOutOfRangeException(nameof(notificationType), "Argument is not a valid enum member");
            }

            // assemble our request message
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, channelUri);
            //
            // set the content (along with the content-type header)
            switch (notificationType)
            {
                case NotificationType.Badge:
                case NotificationType.Tile:
                case NotificationType.Toast:
                    // NOTE: we encode using UTF8 as that is what Microsoft used in their sample code
                    requestMessage.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
                    requestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
                    break;
                case NotificationType.Raw:
                    // NOTE: we encode using UTF8 as that is what Microsoft used in their sample code
                    requestMessage.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
                    requestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                    break;
                default:
                    throw new Exception("invalid code path");
            }
            //
            // set the authorization header
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            //
            // set the mandatory WNS headers
            requestMessage.Headers.Add("X-WNS-Type", notificationType.ToStringValue()!);
            //
            // set optional WNS headers
            if (requestOptions?.CacheWhileClientIsOffline != null)
            {
                requestMessage.Headers.Add("X-WNS-Cache-Policy", requestOptions.Value.CacheWhileClientIsOffline.Value ? "cache" : "no-cache");
            }
            if (requestOptions?.Priority != null)
            {
                // for more information on the priority levels (and why they need to be set on time-critical and raw notifications):
                // see: https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/wns-notification-priorities
                requestMessage.Headers.Add("X-WNS-PRIORITY", ((int)requestOptions.Value.Priority!).ToString());
            }
            if (requestOptions?.RequestDeviceAndConnectionStatus != null)
            {
                requestMessage.Headers.Add("X-WNS-RequestForStatus", requestOptions.Value.RequestDeviceAndConnectionStatus.Value ? "true" : "false");
            }
            if (requestOptions?.Tag != null)
            {
                // NOTE: this option is only used when sending tile notifications
                if (notificationType != NotificationType.Tile)
                {
                    throw new ArgumentException("The tag request option may only be supplied for tile notifications");
                }
                // NOTE: Microsoft's spec says that this tag should be alphanumeric but does not limit the characters or character set;
                //       in the future we may want to add a check here to verify that the argument passes whatever alphanumeric filter Microsoft intended the field to be limited to
                //  see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#x-wns-tag
                //
                requestMessage.Headers.Add("X-WNS-Tag", requestOptions.Value.Tag);
            }
            if (requestOptions?.TimeToLive != null)
            {
                // NOTE: Microsoft specifies this as integer value (a count of seconds), but does not specify the minimum value (which is presumably zero) or the maximum value;
                //       in the future we may want to change the type used to represent this integer and throw an exception if the provided value is out of range
                // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#x-wns-ttl
                //
                requestMessage.Headers.Add("X-WNS-TTL", requestOptions.Value.TimeToLive.Value.ToString());
            }
            //
            // set optional WNS headers (Windows Phone only)
            if (requestOptions?.SuppressPopup != null)
            {
                requestMessage.Headers.Add("X-WNS-SuppressPopup", requestOptions.Value.SuppressPopup.Value ? "true" : "false");
            }
            if (requestOptions?.Group != null)
            {
                // NOTE: Microsoft's spec says that this tag should be alphanumeric but does not limit the characters or character set;
                //       in the future we may want to add a check here to verify that the argument passes whatever alphanumeric filter Microsoft intended the field to be limited to
                //  see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#x-wns-group
                //
                requestMessage.Headers.Add("X-WNS-Group", requestOptions.Value.Group!);
            }

            // send our request (and capture the response)
            using (var httpClient = new HttpClient())
            {
                HttpResponseMessage responseMessage;
                try
                {
                    responseMessage = await httpClient.SendAsync(requestMessage);
                }
                catch (HttpRequestException)
                {
                    // network/http error (connectivity, dns, tls)
                    return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.NetworkError);
                }
                catch (TaskCanceledException ex)
                {
                    if (ex.InnerException?.GetType() == typeof(TimeoutException))
                    {
                        // timeout
                        return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.Timeout);
                    }
                    else
                    {
                        // we should not have any other TaskCanceledExceptions
                        throw;
                    }
                }

                // capture any custom WNS headers returned with the response; these are all optional
                var responseDebugHeaders = new SendNotificationResponseDebugHeaders();
                //
                // X-WNS-Debug-Trace
                if (responseMessage.Headers.Contains("X-WNS-Debug-Trace") == true)
                {
                    var responseDebugTraceHeaderAsList = responseMessage.Headers.GetValues("X-WNS-Debug-Trace").ToList();
                    if (responseDebugTraceHeaderAsList.Count == 1)
                    {
                        // capture the header (which is a string)
                        responseDebugHeaders.XWnsDebugTrace = responseDebugTraceHeaderAsList.First();
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-Debug-Trace\" is malformed: [" + String.Join(", ", responseDebugTraceHeaderAsList) + "]");
                    }
                }
                //
                // X-WNS-DeviceConnectionStatus
                if (responseMessage.Headers.Contains("X-WNS-DeviceConnectionStatus") == true)
                {
                    var responseDeviceConnectionStatusHeaderAsList = responseMessage.Headers.GetValues("X-WNS-DeviceConnectionStatus").ToList();
                    if (responseDeviceConnectionStatusHeaderAsList.Count == 1)
                    {
                        // capture the header (which is a string); we will reduce this to an enum value [ "connected", "disconnected", "tempconnected" ]
                        var deviceConnectionStatusAsString = responseDeviceConnectionStatusHeaderAsList.First();
                        var deviceConnectionStatus = MorphicEnum<SendNotificationResponseDebugHeaders.DeviceConnectionStatusOption>.FromStringValue(deviceConnectionStatusAsString);
                        if (deviceConnectionStatus == null)
                        {
                            responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-DeviceConnectionStatus\" contains unknown value \"" + deviceConnectionStatusAsString + "\"");
                        } 
                        else
                        {
                            responseDebugHeaders.XWnsDeviceConnectionStatus = deviceConnectionStatus;
                        }
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-DeviceConnectionStatus\" is malformed: [" + String.Join(", ", responseDeviceConnectionStatusHeaderAsList) + "]");
                    }
                }
                //
                // X-WNS-Error-Description
                if (responseMessage.Headers.Contains("X-WNS-Error-Description") == true)
                {
                    var responseErrorDescriptionHeaderAsList = responseMessage.Headers.GetValues("X-WNS-Error-Description").ToList();
                    if (responseErrorDescriptionHeaderAsList.Count == 1)
                    {
                        // capture the header (which is a string)
                        responseDebugHeaders.XWnsErrorDescription = responseErrorDescriptionHeaderAsList.First();
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-Error-Description\" is malformed: [" + String.Join(", ", responseErrorDescriptionHeaderAsList) + "]");
                    }
                }
                //
                // X-WNS-Msg-ID
                if (responseMessage.Headers.Contains("X-WNS-Msg-ID") == true)
                {
                    var responseMessageIdHeaderAsList = responseMessage.Headers.GetValues("X-WNS-Msg-ID").ToList();
                    if (responseMessageIdHeaderAsList.Count == 1)
                    {
                        // NOTE: per the specification, this header should never be longer than 16 characters; however in case it grows in the future, this implementation
                        //       does not enforce any specific length limit on the response from WNS

                        // capture the header (which is a string)
                        responseDebugHeaders.XWnsMessageId = responseMessageIdHeaderAsList.First();
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-Msg-ID\" is malformed: [" + String.Join(", ", responseMessageIdHeaderAsList) + "]");
                    }
                }
                //
                // X-WNS-Status
                // NOTE: we capture the status as a string as a sanity check that it matches the undocumented X-WNS-NotificationStatus response
                string? statusAsString = null;
                if (responseMessage.Headers.Contains("X-WNS-Status") == true)
                {
                    var responseStatusHeaderAsList = responseMessage.Headers.GetValues("X-WNS-Status").ToList();
                    if (responseStatusHeaderAsList.Count == 1)
                    {
                        // capture the header (which is a string); we will reduce this to an enum value [ "received", "dropped", "channelthrottled" ] later
                        statusAsString = responseStatusHeaderAsList.First();
                        var status = MorphicEnum<SendNotificationResponseDebugHeaders.StatusOption>.FromStringValue(statusAsString);
                        if (status == null)
                        {
                            responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-Status\" contains unknown value \"" + statusAsString + "\"");
                        }
                        else
                        {
                            responseDebugHeaders.XWnsStatus = status;
                        }
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-Status\" is malformed: [" + String.Join(", ", responseStatusHeaderAsList) + "]");
                    }
                }
                // X-WNS-NotificationStatus
                // NOTE: in preliminary testing, this appears to be a duplicated of X-WNS-Status when X-WNS-RequestForStatus was set to true in the request headers;
                //       out of an abundance of caution we are validating that the two match (when both are present), to avoid any edge cases where they might potentially differ
                if (responseMessage.Headers.Contains("X-WNS-NotificationStatus") == true)
                {
                    var responseNotificationStatusHeaderAsList = responseMessage.Headers.GetValues("X-WNS-NotificationStatus").ToList();
                    if (responseNotificationStatusHeaderAsList.Count == 1)
                    {
                        // capture the header (which is a string)
                        var notificationStatusAsString = responseNotificationStatusHeaderAsList.First();
                        if (notificationStatusAsString != statusAsString)
                        {
                            responseDebugHeaders.AddHeaderParsingError("Headers \"X-WNS-Status\" and \"X-WNS-NotificationStatus\" do not match: " + "\"" + (statusAsString ?? "<null>") + "\" vs. \"" + notificationStatusAsString + "\"");
                        }
                    }
                    else
                    {
                        // NOTE: if this debugging information is not a single header entry, we should log the irregularity (and then gracefully degrade by ignoring the field)
                        responseDebugHeaders.AddHeaderParsingError("Header \"X-WNS-NotificationStatus\" is malformed: [" + String.Join(", ", responseNotificationStatusHeaderAsList) + "]");
                    }
                }

                switch (responseMessage.StatusCode)
                {
                    case HttpStatusCode.OK:
                        {
                            // NOTE: the debug headers indicate if the message was accepted, dropped, blocked, etc.
                            // NOTE: technically we are returning the status twice here; the intent is to make sure that the caller pays attention to the result status (to know
                            //       whether to unsubscribe a dead channel, etc.)
                            // NOTE: technically the Status response is an optional debug header
                            var result = new SendNotificationResult()
                            {
                                Status = responseDebugHeaders.XWnsStatus,
                                ResponseDebugHeaders = responseDebugHeaders
                            };
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.SuccessResult(result);
                        }
                    case HttpStatusCode.BadRequest:
                        {
                            // invalid headers; this is most likely a defect in our code
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.CodeHasBug(responseDebugHeaders));
                        }
                    case HttpStatusCode.Unauthorized:
                        {
                            var wwwAuthenticateHeaders = responseMessage.Headers.WwwAuthenticate;
                            if (wwwAuthenticateHeaders != null)
                            {
                                foreach (var wwwAuthenticateHeader in wwwAuthenticateHeaders!)
                                {
                                    if (wwwAuthenticateHeader.Scheme == "Bearer")
                                    {
                                        // NOTE: in our testing, the "WWW-Authenticate" header returned the following when the token was expired
                                        //       WWW-Authenticate: Bearer error="invalid_request",error_description="Token expired"
                                        if (wwwAuthenticateHeader.Parameter?.Contains("Token expired") == true)
                                        {
                                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.AccessTokenIsExpired(responseDebugHeaders));
                                        }

                                        // NOTE: in our testing, the "WWW-Authenticate" header returned the following when the token was invalid
                                        //       WWW-Authenticate: Bearer error="invalid_request",error_description="Invalid token"
                                        if (wwwAuthenticateHeader.Parameter?.Contains("Invalid token") == true)
                                        {
                                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.AccessTokenIsInvalid(responseDebugHeaders));
                                        }
                                    }
                                }
                            }

                            // if we could not determine the reason the request was unauthorized, return the error as AccessTokenIsExpired; this seems consistent with Microsoft's documentation
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.AccessTokenIsInvalid(responseDebugHeaders));
                        }
                    case HttpStatusCode.Forbidden:
                        {
                            // NOTE: according to Microsoft's documentation, this indicates that the caller likely requested the access token for this channelUri using the wrong app's credentials
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.AccessTokenIsMismatched(responseDebugHeaders));
                        }
                    case HttpStatusCode.NotFound:
                        {
                            // NOTE: according to Microsoft's documentation, this indicates that the caller likely requested the access token for this channelUri using the wrong app's credentials
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.ChannelNotFound(responseDebugHeaders));
                        }
                    case HttpStatusCode.MethodNotAllowed:
                        {
                            // invalid request method; this is most likely a defect in our code
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.CodeHasBug(responseDebugHeaders));
                        }
                    case HttpStatusCode.NotAcceptable:
                        {
                            // our cloud service has exceeded its limits; we need to throttle notifications (broadly) and some clients might need to seek an alternate push method
                            // NOTE: the caller MUST deal with this, as it effectively means that our cloud service is being targeted as an abuser of the WNS system (which means
                            //       that we are currently unable to send the number of notifications which we are designed and/or expect to be sending)
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.ThrottleLimitExceeded(responseDebugHeaders));
                        }
                    case HttpStatusCode.Gone:
                        {
                            // NOTE: according to Microsoft's documentation, this indicates that the caller likely requested the access token for this channelUri using the wrong app's credentials
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.ChannelIsExpired(responseDebugHeaders));
                        }
                    case HttpStatusCode.RequestEntityTooLarge:
                        {
                            // NOTE: the push notification was too large (i.e. >5,000 bytes, per Microsoft's documentation) and was therefore rejected
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.PayloadTooLarge(responseDebugHeaders));
                        }
                    case HttpStatusCode.InternalServerError:
                        {
                            // NOTE: if our caller receives this error, we must log the message (and ideally alert devops); the caller should also back off and then resend
                            // NOTE: ideally we would also update the status on our internal "system status" page to show whether or not we had availability problems with WNS
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.InternalServerError(responseDebugHeaders));
                        }
                    case HttpStatusCode.ServiceUnavailable:
                        {
                            // NOTE: if our caller receives this error, we must log the message (and ideally alert devops); the caller should also back off and then resend
                            // NOTE: ideally we would also update the status on our internal "system status" page to show whether or not we had availability problems with WNS
                            // see: https://docs.microsoft.com/en-us/previous-versions/windows/apps/hh868245(v=win.10)#response-codes
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.ServiceUnavailable(responseDebugHeaders));
                        }
                    default:
                        {
                            // NOTE: there are _no other_ status codes documented in Microsoft's documentation, but others are technically possible
                            // NOTE: our caller SHOULD immediately alert devops if any unexpected status code is received, and SHOULD back off and resend
                            // NOTE: ideally we would also update the status on our internal "system status" page to show whether or not we had availability problems with WNS
                            return IMorphicResult<SendNotificationResult, SendNotificationError>.ErrorResult(SendNotificationError.HttpError(responseMessage.StatusCode, responseDebugHeaders));
                        }
                }
            }
        }
    }
}
