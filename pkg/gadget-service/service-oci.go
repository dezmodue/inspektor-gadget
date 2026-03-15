// Copyright 2024-2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gadgetservice

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (s *Service) initOperators() error {
	for op, globalParams := range s.operators {
		err := op.Init(globalParams)
		if err != nil {
			return fmt.Errorf("initializing operator %s: %w", op.Name(), err)
		}
	}
	return nil
}

func (s *Service) GetOperatorMap() map[operators.DataOperator]*params.Params {
	return s.operators
}

func (s *Service) GetGadgetInfo(ctx context.Context, req *api.GetGadgetInfoRequest) (*api.GetGadgetInfoResponse, error) {
	metricAttribs := attribute.NewSet(
		attribute.KeyValue{Key: "gadget_image", Value: attribute.StringValue(req.ImageName)},
	)
	defer s.ctrGetGadgetInfo.Add(context.Background(), 1, metric.WithAttributeSet(metricAttribs))

	if req.Version != api.VersionGadgetInfo {
		return nil, fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetInfo, req.Version)
	}

	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil {
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, fmt.Errorf("authentication information is not TLS: %v", p.AuthInfo)
		}

		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		s.logger.Infof("[%s] GetGadgetInfo(%q)", subject, req.ImageName)
	}

	if req.Flags&api.GadgetInfoRequestFlagUseInstance != 0 {
		if s.instanceMgr == nil {
			return nil, fmt.Errorf("instance manager not initialized")
		}
		gi := s.instanceMgr.LookupInstance(req.ImageName)
		if gi == nil {
			return nil, fmt.Errorf("instance %s not found", req.ImageName)
		}
		gadgetInfo, err := gi.GadgetInfo()
		if err != nil {
			return nil, err
		}
		return &api.GetGadgetInfoResponse{GadgetInfo: gadgetInfo}, nil
	}

	// Get all available operators
	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}

	gadgetCtx := gadgetcontext.New(
		ctx,
		req.ImageName,
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithAsRemoteCall(true),
		gadgetcontext.IncludeExtraInfo(req.RequestExtraInfo),
	)

	gi, err := s.runtime.GetGadgetInfo(gadgetCtx, s.runtime.ParamDescs().ToParams(), req.ParamValues)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}
	return &api.GetGadgetInfoResponse{GadgetInfo: gi}, nil
}

func (s *Service) RunGadget(runGadget api.GadgetManager_RunGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	attachRequest := ctrl.GetAttachRequest()
	if attachRequest != nil {
		err = s.validateNonInteractivePolicy(nil, true, false)
		if err != nil {
			return err
		}

		if attachRequest.Version != api.VersionGadgetRunProtocol {
			return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, attachRequest.Version)
		}
		if s.instanceMgr == nil {
			return errors.New("instance manager not initialized")
		}

		s.ctrAttachGadget.Add(context.Background(), 1)
		return s.instanceMgr.AttachToGadgetInstance(attachRequest.Id, runGadget)
	}

	ociRequest := ctrl.GetRunRequest()
	if ociRequest == nil {
		return fmt.Errorf("expected first control message to be gadget run request")
	}

	metricAttribs := attribute.NewSet(
		attribute.KeyValue{Key: "gadget_image", Value: attribute.StringValue(ociRequest.ImageName)},
	)
	defer s.ctrRunGadget.Add(context.Background(), 1, metric.WithAttributeSet(metricAttribs))

	p, ok := peer.FromContext(runGadget.Context())
	if ok && p.AuthInfo != nil {
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return fmt.Errorf("authentication information are not TLS: %v", p.AuthInfo)
		}

		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		s.logger.Infof("[%s] RunGadget(%q)", subject, ociRequest.ImageName)
	}

	if ociRequest.Version != api.VersionGadgetRunProtocol {
		return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, ociRequest.Version)
	}

	err = s.validateFilterParams(ociRequest.ParamValues)
	if err != nil {
		return err
	}

	err = s.validateNonInteractivePolicy(ociRequest, false, false)
	if err != nil {
		return err
	}

	err = s.validateRequestTokenListCRDPermission(runGadget.Context(), ociRequest)
	if err != nil {
		return err
	}

	// Create payload buffer
	outputBuffer := make(chan *api.GadgetEvent, s.eventBufferLength)

	// Create a new logger that logs to gRPC and falls back to the standard logger when it failed to send the message
	logger := logger.NewFromGenericLogger(&Logger{
		send: func(event *api.GadgetEvent) error {
			select {
			case outputBuffer <- event:
			default:
				return fmt.Errorf("output buffer full")
			}
			return nil
		},
		level:          logger.Level(ociRequest.LogLevel),
		fallbackLogger: s.logger,
	})

	for k, v := range ociRequest.ParamValues {
		logger.Debugf("param %s: %s", k, v)
	}

	done := make(chan bool)
	defer func() {
		close(done)
	}()

	// Build a simple operator that subscribes to all events and forwards them
	svc := simple.New("svc",
		simple.WithPriority(50000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			log := gadgetCtx.Logger()

			go func() {
				// Receive control messages
				for {
					msg, err := runGadget.Recv()
					if err != nil {
						s.logger.Warnf("error on connection: %v", err)
						gadgetCtx.Cancel()
						return
					}
					switch msg.Event.(type) {
					case *api.GadgetControlRequest_StopRequest:
						log.Debugf("received stop request")
						gadgetCtx.Cancel()
						return
					default:
						s.logger.Warn("received unexpected request")
					}
				}
			}()

			go func() {
				// Message pump to handle slow readers
				for {
					select {
					case ev := <-outputBuffer:
						runGadget.Send(ev)
					case <-done:
						return
					}
				}
			}()

			seq := uint32(0)
			var seqLock sync.Mutex

			gi, err := gadgetCtx.SerializeGadgetInfo(false)
			if err != nil {
				return fmt.Errorf("serializing gadget info: %w", err)
			}

			// datasource mapping; we're sending an array of available DataSources including a
			// DataSourceID; this ID will be used when sending actual data and needs to be remapped
			// to the actual DataSource on the client later on
			dsLookup := make(map[string]uint32)
			for i, ds := range gi.DataSources {
				ds.Id = uint32(i)
				dsLookup[ds.Name] = ds.Id
			}

			// todo: skip DataSources we're not interested in

			for _, ds := range gadgetCtx.GetDataSources() {
				dsID := dsLookup[ds.Name()]
				ds.SubscribePacket(func(ds datasource.DataSource, packet datasource.Packet) error {
					d, _ := proto.Marshal(packet.Raw())

					event := &api.GadgetEvent{
						Type:         api.EventTypeGadgetPayload,
						Payload:      d,
						DataSourceID: dsID,
					}

					seqLock.Lock()
					seq++
					event.Seq = seq

					// Try to send event; if outputBuffer is full, it will be dropped by taking
					// the default path.
					select {
					case outputBuffer <- event:
					default:
					}
					seqLock.Unlock()
					return nil
				}, 1000000) // TODO: static int?
			}

			// Send gadget information
			d, _ := proto.Marshal(gi)
			err = runGadget.Send(&api.GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			})
			if err != nil {
				s.logger.Warnf("sending gadgetInfo: %v", err)
			}
			s.logger.Debugf("sent gadget info")

			return nil
		}),
	)

	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}
	ops = append(ops, svc)
	effectiveTimeout := s.effectiveTimeout(time.Duration(ociRequest.Timeout))

	gadgetCtx := gadgetcontext.New(
		runGadget.Context(),
		ociRequest.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithArgs(ociRequest.Args...),
		gadgetcontext.WithToken(ociRequest.Token),
		gadgetcontext.WithTimeout(effectiveTimeout),
		gadgetcontext.WithAsRemoteCall(true),
	)

	runtimeParams := s.runtime.ParamDescs().ToParams()
	runtimeParams.CopyFromMap(ociRequest.ParamValues, "runtime.")

	err = s.runtime.RunGadget(gadgetCtx, runtimeParams, ociRequest.ParamValues)
	if err != nil {
		return err
	}
	return nil
}

const (
	operatorFilterParamKey      = "operator.filter.filter"
	namespaceFilterClausePrefix = "k8s.namespace=="
	namespaceFilterValuePattern = `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	podnameFilterClausePrefix   = "k8s.podname~"
	// podnameFilterValuePattern allows pod names and pod name patterns with a single wildcard
	// this is sufficient to cover both specific pod targeting and controller-level targeting (e.g. all pods of a deployment) while keeping the pattern simple. 
	// The pattern requires at least one character before the first dash to avoid matching invalid pod names and to ensure that the pattern is specific enough.
	podnameFilterValuePattern = `^[a-zA-Z0-9]+-([a-zA-Z0-9\*]*)?(-[a-zA-Z0-9\*]*)?$`
)

var (
	namespaceFilterValueRegex = regexp.MustCompile(namespaceFilterValuePattern)
	podnameFilterValueRegex   = regexp.MustCompile(podnameFilterValuePattern)
)

// validateFilterParams checks that paramValues satisfies the filter requirements
// configured on the service via SetFilterRequirements.
func (s *Service) validateFilterParams(paramValues map[string]string) error {
	if s.requireNamespace && !hasNamespaceFilter(paramValues) {
		return fmt.Errorf("%q must include %q where VALUE matches %q",
			operatorFilterParamKey, "k8s.namespace==VALUE", namespaceFilterValuePattern)
	}
	if s.requirePodname && !hasPodnameFilter(paramValues) {
		return fmt.Errorf("%q must include %q where VALUE matches %q",
			operatorFilterParamKey, "k8s.podname~VALUE", podnameFilterValuePattern)
	}
	return nil
}

func hasFilterClause(paramValues map[string]string, prefix string, regex *regexp.Regexp) bool {
	for key, value := range paramValues {
		if key != operatorFilterParamKey && !strings.HasPrefix(key, operatorFilterParamKey+".") {
			continue
		}

		for _, filter := range api.SplitStringWithEscape(value, ',') {
			filter = strings.TrimSpace(filter)
			if !strings.HasPrefix(filter, prefix) {
				continue
			}

			v := strings.TrimSpace(strings.TrimPrefix(filter, prefix))
			if regex.MatchString(v) {
				return true
			}
		}
	}

	return false
}

func hasNamespaceFilter(paramValues map[string]string) bool {
	return hasFilterClause(paramValues, namespaceFilterClausePrefix, namespaceFilterValueRegex)
}

func hasPodnameFilter(paramValues map[string]string) bool {
	return hasFilterClause(paramValues, podnameFilterClausePrefix, podnameFilterValueRegex)
}

func hasDetachArg(args []string) bool {
	for _, arg := range args {
		if arg == "--detach" || strings.HasPrefix(arg, "--detach=") {
			return true
		}
	}

	return false
}

func hasAttachArg(args []string) bool {
	for _, arg := range args {
		if arg == "--attach" || strings.HasPrefix(arg, "--attach=") {
			return true
		}
	}

	return false
}

func (s *Service) validateNonInteractivePolicy(request *api.GadgetRunRequest, attachRequest, createRequest bool) error {
	if !s.denyNonInteractive {
		return nil
	}

	if attachRequest {
		return fmt.Errorf("requests including --attach are denied by --deny-non-interactive policy")
	}

	if createRequest {
		return fmt.Errorf("requests including --detach are denied by --deny-non-interactive policy")
	}

	if request != nil && hasDetachArg(request.Args) {
		return fmt.Errorf("requests including --detach are denied by --deny-non-interactive policy")
	}

	if request != nil && hasAttachArg(request.Args) {
		return fmt.Errorf("requests including --attach are denied by --deny-non-interactive policy")
	}

	return nil
}

func namespaceFromFilterParams(paramValues map[string]string) (string, error) {
	namespaceSet := make(map[string]struct{})

	for key, value := range paramValues {
		if key != operatorFilterParamKey && !strings.HasPrefix(key, operatorFilterParamKey+".") {
			continue
		}

		for _, filter := range api.SplitStringWithEscape(value, ',') {
			filter = strings.TrimSpace(filter)
			if !strings.HasPrefix(filter, namespaceFilterClausePrefix) {
				continue
			}

			namespace := strings.TrimSpace(strings.TrimPrefix(filter, namespaceFilterClausePrefix))
			if !namespaceFilterValueRegex.MatchString(namespace) {
				continue
			}

			namespaceSet[namespace] = struct{}{}
		}
	}

	if len(namespaceSet) == 0 {
		return "", fmt.Errorf("missing valid %q clause", namespaceFilterClausePrefix+"VALUE")
	}

	if len(namespaceSet) > 1 {
		namespaces := make([]string, 0, len(namespaceSet))
		for ns := range namespaceSet {
			namespaces = append(namespaces, ns)
		}
		return "", fmt.Errorf("multiple namespaces in filter are not supported: %s", strings.Join(namespaces, ","))
	}

	for ns := range namespaceSet {
		return ns, nil
	}

	return "", errors.New("unexpected namespace extraction failure")
}

func (s *Service) validateRequestTokenListCRDPermission(ctx context.Context, request *api.GadgetRunRequest) error {
	if request == nil {
		return nil
	}

	if !s.validateToken {
		return nil
	}

	token := api.EffectiveRequestToken(request.Args, request.Token)
	if token == "" {
		return errors.New("missing request token")
	}

	namespace, err := namespaceFromFilterParams(request.ParamValues)
	if err != nil {
		return fmt.Errorf("resolving namespace for token authorization: %w", err)
	}

	identity := "unknown"
	targetResource := "auths.authorization.gadget.kinvolk.io"

	if s.tokenListCRDAuthzChecker != nil {
		err = s.tokenListCRDAuthzChecker(ctx, token, namespace)
	} else {
		authzClientset := s.authzKubeClientset
		if authzClientset == nil {
			return errors.New("token authorization clientset is not configured")
		}

		identity, err = checkTokenCanListAuthsInNamespace(ctx, authzClientset, token, namespace)
	}
	if err != nil {
		s.logger.Warnf("token authorization failed: identity=%s namespace=%s resource=%s reason=%v",
			identity, namespace, targetResource, err)
		return fmt.Errorf("token is not authorized to list %q in namespace %q: %w", targetResource, namespace, err)
	}

	s.logger.Infof("token authorization succeeded: identity=%s namespace=%s resource=%s",
		identity, namespace, targetResource)

	return nil
}

func checkTokenCanListAuthsInNamespace(ctx context.Context, authzClientset kubernetes.Interface, token, namespace string) (string, error) {
	if authzClientset == nil {
		return "unknown", errors.New("nil Kubernetes clientset")
	}

	tokenReview, err := authzClientset.AuthenticationV1().TokenReviews().Create(ctx,
		&authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token}},
		metav1.CreateOptions{},
	)
	if err != nil {
		return "unknown", fmt.Errorf("creating TokenReview: %w", err)
	}

	identity := formatTokenIdentity(tokenReview.Status.User.Username, tokenReview.Status.User.UID, tokenReview.Status.User.Groups)

	if tokenReview.Status.Error != "" {
		return identity, fmt.Errorf("token review error: %s", tokenReview.Status.Error)
	}

	if !tokenReview.Status.Authenticated {
		return identity, errors.New("token is not authenticated")
	}

	extra := make(map[string]authorizationv1.ExtraValue, len(tokenReview.Status.User.Extra))
	for key, values := range tokenReview.Status.User.Extra {
		extra[key] = authorizationv1.ExtraValue(values)
	}

	review, err := authzClientset.AuthorizationV1().SubjectAccessReviews().Create(ctx,
		&authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   tokenReview.Status.User.Username,
				UID:    tokenReview.Status.User.UID,
				Groups: tokenReview.Status.User.Groups,
				Extra:  extra,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Group:     "authorization.gadget.kinvolk.io",
					Verb:      "list",
					Resource:  "auths",
				},
			},
		},
		metav1.CreateOptions{},
	)
	if err != nil {
		return identity, fmt.Errorf("creating SubjectAccessReview: %w", err)
	}

	if !review.Status.Allowed {
		if review.Status.Reason != "" {
			return identity, errors.New(review.Status.Reason)
		}
		return identity, errors.New("authorization denied")
	}

	return identity, nil
}

func formatTokenIdentity(username, uid string, groups []string) string {
	groupsVal := "-"
	if len(groups) > 0 {
		groupsVal = strings.Join(groups, ",")
	}

	if username == "" {
		username = "-"
	}
	if uid == "" {
		uid = "-"
	}

	return fmt.Sprintf("user=%s uid=%s groups=%s", username, uid, groupsVal)
}
