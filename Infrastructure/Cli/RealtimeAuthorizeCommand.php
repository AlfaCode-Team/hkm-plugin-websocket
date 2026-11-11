<?php

declare(strict_types=1);

namespace Plugins\WebSocket\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\WebSocket\API\Contracts\ChannelAuthorizer;
use Plugins\WebSocket\API\Contracts\ConnectionIdentifier;
use Plugins\WebSocket\API\Contracts\RequestResponder;
use Plugins\WebSocket\Application\Services\AuthorizeService;
use Plugins\WebSocket\Infrastructure\Server\DenyAllAuthorizer;
use Plugins\WebSocket\Infrastructure\Server\GuestIdentifier;

/**
 * `realtime:authorize` — answer the Go edge's authorization questions.
 *
 * WHAT THIS PROCESS IS FOR
 * ------------------------
 * `edge/` (the Go binary) holds the WebSocket connections and has no database,
 * no session store and no business model. Every question it has — who is this
 * connection, and which channels may it subscribe to — is asked over the bus
 * and answered HERE, by the project's own {@see ChannelAuthorizer}, which is
 * the same one `realtime:serve` calls in-process.
 *
 * So the authorization rule has exactly one implementation. That is the whole
 * reason the edge is a thin process instead of a realtime server in its own
 * right.
 *
 * YOU ONLY NEED THIS IF YOU RUN THE GO EDGE. With `realtime:serve` (PHP on
 * OpenSwoole) the authorizer is called directly and no responder is involved.
 *
 * RUN IT SUPERVISED, AND RUN MORE THAN ONE
 * ----------------------------------------
 * It is on the critical path of every subscribe: while it is down, the edge's
 * requests time out and every subscription is denied — connections succeed and
 * nothing is ever delivered, which is the exact failure this plugin's whole
 * design is arranged to prevent. Request/reply over a bus load-balances across
 * however many are listening, so two or three is cheap insurance.
 */
final class RealtimeAuthorizeCommand extends AbstractCommand
{
    public function __construct(
        private readonly ?RequestResponder $responder = null,
        private readonly ?ChannelAuthorizer $authorizer = null,
        private readonly ?ConnectionIdentifier $identifier = null,
        private readonly ?LoggerPort $logger = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'realtime:authorize';
        $this->description = 'Answer the realtime edge\'s authorization requests over the bus';

        $this->addOption(
            'subject',
            's',
            'The request subject the edge asks on (default: WEBSOCKET_AUTH_SUBJECT or hkm.rt.authorize)',
            acceptsValue: true,
        );
    }

    protected function handle(): int
    {
        // Narrowed to non-empty here rather than at the call: the contract
        // declares non-empty-string because a blank subject subscribes to
        // nothing while reporting success, which is the quietest possible
        // failure for a responder.
        $chosen = \is_string($this->option('subject')) ? trim((string) $this->option('subject')) : '';

        if ($chosen === '') {
            $chosen = trim((string) (env('WEBSOCKET_AUTH_SUBJECT') ?? ''));
        }

        $subject = $chosen !== '' ? $chosen : 'hkm.rt.authorize';

        $this->section('Realtime authorizer');

        if ($this->responder === null) {
            // Refused rather than started. A responder-less process would sit
            // there looking healthy while the edge denied every subscription.
            $this->error(
                'No ' . RequestResponder::class . " is bound, so there is nothing to answer requests on.\n\n"
                . "This is the request/reply seam the Go edge uses. PubSubPort cannot carry it — that port "
                . "promises every subscriber every message, which is the opposite of one responder "
                . "answering one asker — so the project supplies it:\n\n"
                . "  ->withPorts([ /* … */ ])\n"
                . "  // and in a module's register():\n"
                . '  $container->bind(' . RequestResponder::class . '::class, fn ($c) => new NatsResponder(...));'
                . "\n\nAbout twenty lines over NATS: subscribe, and publish the answer to the message's "
                . 'reply subject. If you run `realtime:serve` instead of the Go edge, you do not need '
                . 'this command at all.',
            );

            return self::FAILURE;
        }

        $authorizer = $this->authorizer ?? new DenyAllAuthorizer($this->logger);
        $identifier = $this->identifier ?? new GuestIdentifier($this->logger);

        if ($this->authorizer === null) {
            $this->warning(
                'No ' . ChannelAuthorizer::class . ' is bound, so EVERY subscription will be refused. '
                . 'The responder will run and answer correctly — the answer is just always "no".',
            );
        }

        if ($this->identifier === null) {
            $this->warning(
                'No ' . ConnectionIdentifier::class . ' is bound, so every connection is a guest and '
                . 'any channel scoped to a user is denied. Public channels still work.',
            );
        }

        $maxChannels = max(1, (int) (env('WEBSOCKET_MAX_CHANNELS') ?: 64));

        $service = new AuthorizeService(
            authorizer: $authorizer,
            identifier: $identifier,
            maxChannels: $maxChannels,
            logger: $this->logger,
        );

        $this->muted('Responder  : ' . $this->responder->describe());
        $this->muted('Subject    : ' . $subject);
        $this->muted('Authorizer : ' . $authorizer::class);
        $this->muted('Identifier : ' . $identifier::class);
        $this->muted('Max channels per request: ' . $maxChannels);
        $this->newLine();
        $this->success('Answering. Ctrl-C to stop.');
        $this->muted(
            'Nothing is printed per request — a line per subscribe on a busy edge is a log nobody '
            . 'reads. Refusals and failures go to the logger.',
        );

        try {
            $this->responder->respond($subject, $service->handle(...));
        } catch (\Throwable $e) {
            // A lost subscription is reported, never swallowed: an authorizer
            // that quietly stopped answering looks exactly like an application
            // in which nobody is subscribing.
            $this->newLine();
            $this->error('The responder stopped: ' . $e->getMessage());
            $this->muted(
                'While this is down the edge denies every subscription, so clients connect and '
                . 'receive nothing. Supervise it, and run more than one — request/reply load-balances '
                . 'across every listener.',
            );

            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
