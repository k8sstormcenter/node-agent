package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/applicationprofile"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/k8s"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/net"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/networkneighborhood"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/process"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/picatz/xcel"
)

var _ RuleEvaluator = (*CEL)(nil)

type CEL struct {
	env             *cel.Env
	objectCache     objectcache.ObjectCache
	programCache    map[string]cel.Program
	cacheMutex      sync.RWMutex
	typeMutex       sync.RWMutex
	evalContextPool sync.Pool
	ta              xcel.TypeAdapter
	tp              *xcel.TypeProvider
}

func NewCEL(objectCache objectcache.ObjectCache, cfg config.Config) (*CEL, error) {
	ta, tp := xcel.NewTypeAdapter(), xcel.NewTypeProvider()

	// Register a generic event template that has all possible event fields
	// This will be used for all event types (exec, network, dns, http, etc.)
	eventObj, eventTyp := xcel.NewObject(&utils.CelEventImpl{})
	xcel.RegisterObject(ta, tp, eventObj, eventTyp, utils.CelFields)

	// Register "event" variable for all event types
	// Also register "http" variable for HTTP events
	envOptions := []cel.EnvOption{
		cel.Variable("event", eventTyp), // All events accessible via "event" variable
		cel.Variable("http", eventTyp),  // HTTP events also accessible via "http" variable
		cel.Variable("eventType", cel.StringType),
		cel.CustomTypeAdapter(ta),
		cel.CustomTypeProvider(tp),
		ext.Strings(),
		k8s.K8s(objectCache.K8sObjectCache(), cfg),
		applicationprofile.AP(objectCache, cfg),
		networkneighborhood.NN(objectCache, cfg),
		parse.Parse(cfg),
		net.Net(cfg),
		process.Process(cfg),
	}

	env, err := cel.NewEnv(envOptions...)
	if err != nil {
		return nil, err
	}
	c := &CEL{
		env:          env,
		objectCache:  objectCache,
		programCache: make(map[string]cel.Program),
		ta:           ta,
		tp:           tp,
	}

	c.evalContextPool.New = func() interface{} {
		return make(map[string]any, 1)
	}

	return c, nil
}

func (c *CEL) registerExpression(expression string) error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// Check if already compiled
	if _, exists := c.programCache[expression]; exists {
		return nil
	}

	ast, issues := c.env.Compile(expression)
	if issues != nil {
		return fmt.Errorf("failed to compile expression: %s", issues.Err())
	}

	program, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return fmt.Errorf("failed to create program: %s", err)
	}

	c.programCache[expression] = program
	return nil
}

func (c *CEL) getOrCreateProgram(expression string) (cel.Program, error) {
	c.cacheMutex.RLock()
	if program, exists := c.programCache[expression]; exists {
		c.cacheMutex.RUnlock()
		return program, nil
	}
	c.cacheMutex.RUnlock()

	// If not in cache, compile and cache it
	if err := c.registerExpression(expression); err != nil {
		return nil, err
	}

	c.cacheMutex.RLock()
	program := c.programCache[expression]
	c.cacheMutex.RUnlock()
	return program, nil
}

// createEvalContext creates an evaluation context map from an enriched event
// The context includes the eventType string and the event object wrapped in xcel
// Uses "event" as the variable name, and for HTTP events also adds "http" variable
func (c *CEL) createEvalContext(event *events.EnrichedEvent) map[string]any {
	eventType := event.Event.GetEventType()

	// Wrap event in xcel for CEL field access
	obj, _ := xcel.NewObject(event.Event)

	evalContext := map[string]any{
		"eventType": string(eventType),
		"event":     obj,
	}

	// For HTTP events, also add "http" variable for more natural expressions
	if eventType == utils.HTTPEventType {
		evalContext["http"] = obj
	}

	return evalContext
}

// evaluateProgramWithContext compiles (or retrieves cached) and evaluates a CEL expression
// with the provided evaluation context, returning the CEL result value
func (c *CEL) evaluateProgramWithContext(expression string, evalContext map[string]any) (ref.Val, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return nil, err
	}

	out, _, err := program.Eval(evalContext)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (c *CEL) EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error) {
	eventType := event.Event.GetEventType()
	evalContext := c.createEvalContext(event)

	for _, expression := range expressions {
		if expression.EventType != eventType {
			continue
		}

		out, err := c.evaluateProgramWithContext(expression.Expression, evalContext)
		if err != nil {
			return false, err
		}

		boolVal, ok := out.Value().(bool)
		if !ok {
			return false, fmt.Errorf("rule expression returned %T, expected bool", out.Value())
		}
		if !boolVal {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error) {
	evalContext := c.createEvalContext(event)

	out, err := c.evaluateProgramWithContext(expression, evalContext)
	if err != nil {
		return "", err
	}

	strVal, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf("expression returned %T, expected string", out.Value())
	}
	return strVal, nil
}

func (c *CEL) RegisterHelper(function cel.EnvOption) error {
	extendedEnv, err := c.env.Extend(function)
	if err != nil {
		return err
	}
	c.env = extendedEnv
	return nil
}

func (c *CEL) RegisterCustomType(eventType utils.EventType, obj interface{}) error {
	c.typeMutex.Lock()
	defer c.typeMutex.Unlock()

	// Create new object and type using xcel
	xcelObj, xcelTyp := xcel.NewObject(obj)

	// Register the new object with the existing type adapter/provider
	xcel.RegisterObject(c.ta, c.tp, xcelObj, xcelTyp, xcel.NewFields(xcelObj))

	// Extend the environment with the new variable
	// This preserves all existing types while adding the new one
	extendedEnv, err := c.env.Extend(
		cel.Variable(string(eventType), xcelTyp),
	)
	if err != nil {
		return fmt.Errorf("failed to extend environment with custom type: %w", err)
	}

	c.env = extendedEnv

	// Clear program cache since environment has changed
	c.cacheMutex.Lock()
	c.programCache = make(map[string]cel.Program)
	c.cacheMutex.Unlock()

	return nil
}
