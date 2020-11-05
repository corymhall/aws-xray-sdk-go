// Copyright 2017-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

// Implementing xray tracing using smithy-go middleware https://pkg.go.dev/github.com/awslabs/smithy-go/middleware
// the middleware stack executes steps in a specific order, passing the context down the chain. The final
// step "Deserialize" passes to the HTTP client and receives the results from the client.
//
// There is no separate "send" step so it becomes tricky to add segments after the http request is sent and the response is received.
// The way I have accomplished this is to add segments after receiving the response from the next handler. For example
//
//    func HandleDeserialize(ctx, in) (out, metadata, err) {
//        // anything here happens before the request is passed to the HTTP client
//
//        // get results from the next handler in the chain which will also
//        // contain the results from the HTTP client
//        out, metadata, err = next.HandleDeserialize(ctx, in)
//
//        // this happens after we have received results from the HTTP client
//        BeginSegment(ctx, "name")
//    }
//
// Since creating/closing segments depends on the request Context we need a way to
// pass the context back down the chain with the response. The way I have accomplished
// this is to add the Context to the metadata.
//
// This causes the ordering of the middleware to seem backwards, for example:
//
//       (ctx)                    (ctx)                           (ctx)                 (ctx)
// CompleteMiddleware -> AfterDeserializeMiddleware -> BeforeDeserializeMiddleware -> HTTP client
//       (resp)                   (resp)                          (resp)                (resp)
// CompleteMiddleware <- AfterDeserializeMiddleware <- BeforeDeserializeMiddleware <- HTTP client
//
// The actions in these stages happen after receiving the response from the HTTP client.
// So what is happening here is we pass the context down this chain to the HTTP client which
// then sends the response back to BeforeDeserializeMiddleware to begin the "unmarshal segment".
// The BeforeDeserializeMiddleware then adds the context to the metadata to pass it back to
// AfterDeserializeMiddleware and CompleteMiddleware

package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptrace"
	"reflect"
	"strings"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-xray-sdk-go/internal/logger"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

type xrayContextKey struct{}

func getXRayContextMetadata(metadata middleware.Metadata) (v context.Context) {
	v, _ = metadata.Get(xrayContextKey{}).(context.Context)
	return v
}

func setXRayContextMetadata(ctx context.Context, metadata *middleware.Metadata) {
	metadata.Set(xrayContextKey{}, ctx)
}

func beginSubsegmentV2(ctx context.Context, name string) context.Context {
	ctx, _ = BeginSubsegment(ctx, name)
	return ctx
}

func endSubsegmentV2(ctx context.Context) context.Context {
	seg := GetSegment(ctx)
	if seg == nil {
		return ctx
	}
	seg.Close(nil) // double check this was seg.Close(r.Error)
	ctx = context.WithValue(ctx, ContextKey, seg.parent)

	return ctx
}

type BeforeSerializeMiddleware struct {
	whitelistFilename string
}

func (m *BeforeSerializeMiddleware) ID() string { return "BeforeSerializeMiddleware" }

func (m *BeforeSerializeMiddleware) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (out middleware.SerializeOutput, metadata middleware.Metadata, err error) {
	whitelistJSON := parseWhitelistJSON(m.whitelistFilename)
	whitelist := &jsonMap{}
	err = json.Unmarshal(whitelistJSON, &whitelist.object)
	if err != nil {
		return out, metadata, err
	}

	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown request type %T", req)
	}
	serviceName := awsmiddleware.GetSigningName(ctx)

	params := in.Parameters

	ctx, opseg := BeginSubsegment(ctx, serviceName)
	if opseg == nil {
		return out, metadata, err
	}
	opseg.Lock()
	opseg.Namespace = "aws"

	for k, v := range extractRequestParametersWithContext(ctx, params, whitelist) {
		opseg.GetAWS()[strings.ToLower(addUnderScoreBetweenWords(k))] = v
	}

	opseg.Unlock()

	ctx, _ = BeginSubsegment(ctx, "marshal")

	req.Header.Set(TraceIDHeaderKey, opseg.DownstreamHeader().String())

	return next.HandleSerialize(ctx, in)
}

// * Build: Adds additional metadata to the serialized transport message,
// (e.g. HTTP's Content-Length header, or body checksum). Decorations and
// modifications to the message should be copied to all message attempts.
type AfterBuildMiddleware struct{}

func (m *AfterBuildMiddleware) ID() string { return "AfterBuildMiddleware" }

func (m *AfterBuildMiddleware) HandleBuild(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
	ctx = endSubsegmentV2(ctx) // end marshal

	return next.HandleBuild(ctx, in)
}

// * Finalize: Preforms final preparations needed before sending the message.
// The message should already be complete by this stage, and is only alternated
// to meet the expectations of the recipient, (e.g. Retry and AWS SigV4 request
// signing).

type BeforeFinalizeMiddleware struct{}

func (m *BeforeFinalizeMiddleware) ID() string { return "BeforeFinalizeMiddleware" }

func (m *BeforeFinalizeMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
	ctx, seg := BeginSubsegment(ctx, "attempt")
	if seg == nil {
		return out, metadata, err
	}
	ct, _ := NewClientTrace(ctx)
	ctx = httptrace.WithClientTrace(ctx, ct.httpTrace)

	return next.HandleFinalize(ctx, in)
}

// Not sure if this is after send or stiff before send
type AfterSendMiddleware struct{}

func (m *AfterSendMiddleware) ID() string { return "AfterSendMiddleware" }

func (m *AfterSendMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, err error) {
	// This receives the raw response, or error from the underlying handler
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	curseg := GetSegment(ctx)

	if curseg != nil && curseg.Name == "attempt" {
		// An error could have prevented the connect subsegment from closing,
		// so clean it up here.
		curseg.RLock()
		temp := make([]*Segment, len(curseg.rawSubsegments))
		copy(temp, curseg.rawSubsegments)
		curseg.RUnlock()

		for _, subsegment := range temp {
			if subsegment.getName() == "connect" && subsegment.safeInProgress() {
				subsegment.Close(nil)
				return
			}
		}
	}

	return out, metadata, err
}

// * Deserialize: Reacts to the handler's response returned by the recipient
//
// of the request message. Deserializes the response into a structured type or
// error above stacks can react to.
type BeforeDeserializeMiddleware struct{}

func (m *BeforeDeserializeMiddleware) ID() string { return "BeforeDeserializeMiddleware" }

func (m *BeforeDeserializeMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, err error) {

	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	ctx = endSubsegmentV2(ctx) // end attempt
	ctx = beginSubsegmentV2(ctx, "unmarshal")

	setXRayContextMetadata(ctx, &metadata)

	return out, metadata, err
}

// * Deserialize: Reacts to the handler's response returned by the recipient
//
// of the request message. Deserializes the response into a structured type or
// error above stacks can react to.
type AfterDeserializeMiddleware struct{}

func (m *AfterDeserializeMiddleware) ID() string { return "AfterDeserializeMiddleware" }

func (m *AfterDeserializeMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, err error) {
	// should get result from "OperationDeserializer" so everything after
	// this should be after unmarshal
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	ctx = getXRayContextMetadata(metadata)

	ctx = endSubsegmentV2(ctx)

	setXRayContextMetadata(ctx, &metadata)

	return out, metadata, err
}

type CompleteMiddleware struct {
	whitelistFilename string
}

func (m *CompleteMiddleware) ID() string { return "CompleteMiddleware" }

func (m *CompleteMiddleware) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, err error) {

	whitelistJSON := parseWhitelistJSON(m.whitelistFilename)
	whitelist := &jsonMap{}
	err = json.Unmarshal(whitelistJSON, &whitelist.object)
	if err != nil {
		return out, metadata, err
	}

	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	ctx = getXRayContextMetadata(metadata)

	resp, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		// no response
		return out, metadata, err
	}

	curseg := GetSegment(ctx)

	for curseg != nil && curseg.Namespace != "aws" {
		curseg = curseg.parent
	}
	if curseg == nil {
		return out, metadata, err
	}
	opseg := curseg
	opseg.Lock()

	for k, v := range extractResponseParametersWithContext(ctx, out.Result, whitelist) {
		opseg.GetAWS()[strings.ToLower(addUnderScoreBetweenWords(k))] = v
	}

	opseg.GetAWS()["region"] = awsmiddleware.GetSigningRegion(ctx)
	opseg.GetAWS()["operation"] = awsmiddleware.GetOperationName(ctx)
	opseg.GetAWS()[RequestIDKey], _ = awsmiddleware.GetRequestIDMetadata(metadata)

	if resp != nil {
		opseg.GetHTTP().GetResponse().Status = resp.StatusCode
		opseg.GetHTTP().GetResponse().ContentLength = int(resp.ContentLength)
		if extendedRequestID := resp.Header.Get(S3ExtendedRequestIDHeaderKey); extendedRequestID != "" {
			opseg.GetAWS()[ExtendedRequestIDKey] = extendedRequestID
		}
	}

	opseg.Unlock()
	opseg.Close(nil) // close aws

	return out, metadata, err
}

type BeforeRetryMiddleware struct{}

func (m *BeforeRetryMiddleware) ID() string { return "BeforeRetryMiddleware" }

func (m *BeforeRetryMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
	ctx, _ = BeginSubsegment(ctx, "wait")

	return next.HandleFinalize(ctx, in)
}

type AfterRetryMiddleware struct{}

func (m *AfterRetryMiddleware) ID() string { return "AfterRetryMiddleware" }

func (m *AfterRetryMiddleware) HandleFinalize(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {

	ctx = endSubsegmentV2(ctx)

	return next.HandleFinalize(ctx, in)
}
func addMiddleware(filename string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		if err := stack.Serialize.Add(&BeforeSerializeMiddleware{whitelistFilename: filename}, middleware.Before); err != nil {
			return err
		}
		if err := stack.Build.Add(&AfterBuildMiddleware{}, middleware.After); err != nil {
			return err
		}
		if err := stack.Finalize.Add(&BeforeFinalizeMiddleware{}, middleware.Before); err != nil {
			return err
		}
		if err := stack.Finalize.Insert(&BeforeRetryMiddleware{}, retry.AttemptMiddleware{}.ID(), middleware.Before); err != nil {
			return err
		}
		if err := stack.Finalize.Insert(&AfterRetryMiddleware{}, retry.AttemptMiddleware{}.ID(), middleware.After); err != nil {
			return err
		}
		if err := stack.Deserialize.Insert(&CompleteMiddleware{whitelistFilename: filename}, "AWSRequestIDRetrieverMiddleware", middleware.Before); err != nil { // will be RequestIDRetriever
			return err
		}
		if err := stack.Deserialize.Insert(&AfterDeserializeMiddleware{}, "OperationDeserializer", middleware.Before); err != nil {
			return err
		}
		if err := stack.Deserialize.Insert(&BeforeDeserializeMiddleware{}, "OperationDeserializer", middleware.After); err != nil {
			return err
		}
		if err := stack.Deserialize.Add(&AfterSendMiddleware{}, middleware.After); err != nil {
			return err
		}
		return nil
	}
}

func AddXRayMiddleware() func(*middleware.Stack) error {
	return addMiddleware("")
}

func AddXRayMiddlewareWithFilename(filename string) func(*middleware.Stack) error {
	return addMiddleware(filename)
}

func extractRequestParametersWithContext(ctx context.Context, params interface{}, whitelist *jsonMap) map[string]interface{} {
	valueMap := make(map[string]interface{})

	extractParametersWithContext(ctx, "request_parameters", requestKeyword, params, whitelist, valueMap)
	extractDescriptorsWithContext(ctx, "request_descriptors", requestKeyword, params, whitelist, valueMap)

	return valueMap
}

func extractResponseParametersWithContext(ctx context.Context, params interface{}, whitelist *jsonMap) map[string]interface{} {
	valueMap := make(map[string]interface{})

	extractParametersWithContext(ctx, "response_parameters", responseKeyword, params, whitelist, valueMap)
	extractDescriptorsWithContext(ctx, "response_descriptors", responseKeyword, params, whitelist, valueMap)

	return valueMap
}

func extractParametersWithContext(ctx context.Context, whitelistKey string, rType int, p interface{}, whitelist *jsonMap, valueMap map[string]interface{}) {
	serviceName := awsmiddleware.GetSigningName(ctx)
	operationName := awsmiddleware.GetOperationName(ctx)

	params := whitelist.search("services", serviceName, "operations", operationName, whitelistKey)
	if params != nil {
		children, err := params.children()
		if err != nil {
			logger.Errorf("failed to get values for aws attribute: %v", err)
			return
		}
		for _, child := range children {
			if child != nil {
				var value interface{}
				if rType == responseKeyword {
					value = keyValue(p, child.(string))
				} else if rType == requestKeyword {
					value = keyValue(p, child.(string))
				}
				if (value != reflect.Value{}) {
					valueMap[child.(string)] = value
				}
			}
		}
	}
}

func extractDescriptorsWithContext(ctx context.Context, whitelistKey string, rType int, params interface{}, whitelist *jsonMap, valueMap map[string]interface{}) {
	serviceName := awsmiddleware.GetSigningName(ctx)
	operationName := awsmiddleware.GetOperationName(ctx)

	responseDtr := whitelist.search("services", serviceName, "operations", operationName, whitelistKey)
	if responseDtr != nil {
		items, err := responseDtr.childrenMap()
		if err != nil {
			logger.Errorf("failed to get values for aws attribute: %v", err)
			return
		}
		for k := range items {
			descriptorMap, _ := whitelist.search("services", serviceName, "operations", operationName, whitelistKey, k).childrenMap()
			if rType == requestKeyword {
				insertDescriptorValuesIntoMap(k, params, descriptorMap, valueMap)
			} else if rType == responseKeyword {
				insertDescriptorValuesIntoMap(k, params, descriptorMap, valueMap)
			}
		}
	}
}
