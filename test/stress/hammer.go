package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/trufnetwork/kwil-db/core/client"
	clientType "github.com/trufnetwork/kwil-db/core/client/types"
	"github.com/trufnetwork/kwil-db/core/crypto"
	"github.com/trufnetwork/kwil-db/core/crypto/auth"
	"github.com/trufnetwork/kwil-db/core/gatewayclient"
	"github.com/trufnetwork/kwil-db/core/log"
	"github.com/trufnetwork/kwil-db/core/types"
	"github.com/trufnetwork/kwil-db/core/utils/random"
)

// runLooped executes a basic function with a specified delay between each call
// (note this is not a ticker, which would attempt to keep a regular interval).
// If the function has an error, it is only logged. The function should be a
// closure, getting it's inputs and assigning its outputs in the scope of the
// caller.
func runLooped(ctx context.Context, fn func() error, name string, every time.Duration, logger log.Logger) {
	defer wg.Done()
	if every < 0 { // so caller doesn't need to put an if around this
		return
	}
	for {
		err := fn()
		if err != nil {
			logger.Warn(fmt.Sprintf("%s error: %v", name, err))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(every): // not a ticker, but a wait between runs
		}
	}
}

// hammer is a high level function to begin certain programs designed to
// simulate high utilization. This includes using a test harness type to execute
// actions and make requests with a Kwil new user (unless key is specified),
// using freshly deployed toy datasets that are embedded into this tool. We may
// want to run multiple of these in concurrent goroutines in the future.
func hammer(ctx context.Context, key string, tag string, dbReady chan struct{}) error {
	var err error
	var priv *crypto.Secp256k1PrivateKey
	if key == "" { // only useful with no gas or when spamming non-tx/view calls
		pk, _, err := crypto.GenerateSecp256k1Key(nil)
		if err != nil {
			return err
		}
		priv = pk.(*crypto.Secp256k1PrivateKey)
		fmt.Printf("Generated new key: %x\n", priv.Bytes())
	} else {
		keyBts, err := hex.DecodeString(key)
		if err != nil {
			return err
		}
		priv, err = crypto.UnmarshalSecp256k1PrivateKey(keyBts)
		if err != nil {
			return err
		}
	}
	signer := &auth.EthPersonalSigner{Key: *priv}
	acctID := &types.AccountID{
		Identifier: signer.CompactID(),
		KeyType:    signer.PubKey().Type(),
	}
	fmt.Println("Identity:", acctID)

	logger := log.New(log.WithFormat(log.FormatUnstructured),
		log.WithLevel(log.LevelInfo), log.WithName("STRESS"+tag),
		log.WithWriter(os.Stdout))

	trLogger := logger.New("client" + tag)
	var kwilClt clientType.Client
	if gatewayProvider {
		kwilClt, err = gatewayclient.NewClient(ctx, host, &gatewayclient.GatewayOptions{
			Options: clientType.Options{
				Signer:  signer,
				ChainID: chainId,
				Logger:  trLogger,
			},
		})
	} else {
		kwilClt, err = client.NewClient(ctx, host, &clientType.Options{
			Signer:  signer,
			ChainID: chainId,
			Logger:  trLogger,
		})
	}

	if err != nil {
		return err
	}

	kwilClt = &timedClient{Client: kwilClt, logger: logger, showReqDur: rpcTiming}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // any early return cancels other goroutines

	_, err = kwilClt.Ping(ctx)
	if err != nil {
		return err
	}

	// Bring up the DB test harness with a fresh test database.
	h := &harness{
		Client:              kwilClt,
		concurrentBroadcast: concurrentBroadcast,
		logger:              logger,
		acctID:              acctID,
		signer:              signer,
		nestedLogger:        logger, // caller skip?
		quiet:               quiet,
	}

	if acct, err := kwilClt.GetAccount(ctx, acctID, types.AccountStatusPending); err != nil {
		return err
	} else { //nolint (scoping acct var)
		h.nonce = acct.Nonce
	}

	// action spammer
	if namespace == "" {
		namespace = "stress_" + random.String(8)
	}
	namespace = strings.ToLower(namespace) // lower cased in info.namespaces.name

	asc := newActSchemaClient(h, namespace)

	// try to use this namespace if it exists, otherwise deploy a new one
	res, err := h.Client.Query(ctx, fmt.Sprintf(`select exists (select 1 from info.namespaces where name = '%s');`, namespace), nil, true)
	if err != nil {
		return err
	}
	if len(res.Values) == 0 || len(res.Values[0]) == 0 {
		return errors.New("didn't get a result in namespace query")
	}
	exists := res.Values[0][0].(bool)
	if exists {
		h.printf("act schema: namespace %q already exists, using it", namespace)
	} else if key == "" {
		return fmt.Errorf("namespace %q does not exist, and not DB owner", namespace)
	} else {
		err = asc.deployDB(ctx)
		if err != nil {
			return err
		}
		h.printf("act schema: deployed namespace %q", namespace)
	}

	if dbReady != nil {
		close(dbReady)
	}

	err = asc.getOrCreateUserProfile(ctx, namespace)
	if err != nil {
		return fmt.Errorf("getOrCreateUser: %w", err)
	}

	h.nonceChaos = nonceChaos // after successfully deploying the test db and creating a user in it

	// ## badgering read-only requests to various systems

	// bother the account store
	wg.Add(1)
	go runLooped(ctx, func() error {
		_, err := h.GetAccount(ctx, acctID, types.AccountStatus(rand.Intn(2)))
		return err
	}, "GetAccount", badgerInterval, logger)

	wg.Add(1)
	go runLooped(ctx, func() error {
		notAnAccount := &types.AccountID{
			Identifier: randomBytes(32),
			KeyType:    crypto.KeyTypeEd25519,
		}
		_, err := h.GetAccount(ctx, notAnAccount, types.AccountStatusPending)
		return err
	}, "GetAccount", badgerInterval, logger)

	// bother the authn&kgw
	wg.Add(1)
	go runLooped(ctx, func() error {
		_, err := kwilClt.Call(ctx, namespace, actAuthnOnly, []any{})
		return err
	}, "call authn action", viewInterval, logger)

	// ## "deploy / drop" program - trivial deploy/drop cycle, sometimes
	// immediately dropping. The interval for this one is different since it is
	// a delay after the drop tx confirms before deploying the next, so an
	// interval of 0 is more sensible. Should be updated with an action or two.

	wg.Add(1)
	go runLooped(ctx, func() error {
		junkNamespace := random.String(22)
		junkSchema := makeTestSchemaSQL(junkNamespace)
		asc.h.deployDBAsync(ctx, asc.schemaSQL)
		promise, err := asc.h.deployDBAsync(ctx, junkSchema)
		if err != nil {
			return err
		}
		h.printf("deploying temp namespace %v", junkNamespace)

		if noDrop {
			return nil
		}

		dropNow := fastDropRate > 0 && rand.Intn(fastDropRate) == 0
		if dropNow {
			// drop now
			h.printf("immediately dropping new db %s", junkNamespace)
			err = errors.Join(h.dropDB(ctx, junkNamespace))
		}

		// TODO: in the deploy/drop scenario, there is a lot more to exercise
		// with actions (both view and mutable) here.

		res := <-promise
		if resErr := res.Error(); resErr != nil {
			return errors.Join(err, resErr) // deploy failed, no drop needed
		}
		h.printf("deployed temp db %v", junkNamespace)

		if dropNow {
			return nil // already dropped it
		}

		h.printf("dropping temp db %s", junkNamespace)
		return h.dropDB(ctx, junkNamespace)
	}, "deploy/drop", deployDropInterval, logger)

	// ## "posters" exec/view program - work with the toy social media scheme,
	// concurrently posting and retrieving random posts.

	wg.Add(1)
	go runLooped(ctx, func() error {
		lastPostID, err := asc.lastPostID(ctx, namespace)
		if err != nil {
			return fmt.Errorf("nextPostID: %w", err)
		}
		if lastPostID == nil {
			return nil // will try again
		}
		h.printf("last post ID = %d", lastPostID)

		_, err = kwilClt.Call(ctx, namespace, actGetPost, []any{lastPostID})
		if err != nil {
			return err
		}
		return nil
	}, "get post", viewInterval, logger)

	// Content length is limited by multiple things: message size, max transaction size, block size e.g.:
	//  - "rpc error: code = ResourceExhausted desc = grpc: received message larger than max (5000168 vs. 4194304)"
	//  - "Tx too large. Max size is 1048576, but got 4192304" a little less than 1MiB would be 1<<20 - 1e3
	bigData := makeBigData(contentLen, h.printf)

	// post (actions)
	if maxPosters > 0 {
		operation := "create post (act)"
		posters := make(chan struct{}, maxPosters)
		wg.Add(1)
		go runLooped(ctx,
			asyncFn(ctx, posters, h.printf, operation,
				func() (<-chan asyncResp, error) {
					var content string
					if variableLen {
						content = bigData[:rand.Intn(contentLen)+1] // random.String(rand.Intn(maxContentLen) + 1) // randomBytes(maxContentLen)
					} else {
						content = bigData[:contentLen]
					}
					h.printf("beginning createPostAsync, content len = %d (concurrent with %d others)",
						len(content), len(posters)-1)
					return asc.createPostAsync(ctx, namespace, content)
				},
			),
			operation, postInterval, logger,
		)
	}

	wg.Wait()

	return nil
}

func randomBytes(l int) []byte {
	b := make([]byte, l)
	_, _ = crand.Read(b)
	return b
}
