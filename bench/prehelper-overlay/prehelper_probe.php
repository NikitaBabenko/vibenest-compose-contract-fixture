<?php
// Source-only overlay for the disposable f930 fixture. Never a production endpoint.
// The wrapper bootstraps Laravel and supplies $vnRequest. No queue is dispatched.
use App\Models\Application;
use App\Models\ApplicationDeploymentQueue;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Symfony\Component\Yaml\Yaml;

$vnPins = [
    'app/Jobs/ApplicationDeploymentJob.php' => 'd419c37cbb25a5e3c86b4c4f63b9714603f4e004297723523d39ce5dd46b8c0a',
    'app/Models/Application.php' => '1c80800965d7150ef3627a0f9b4d7b91dfec6c1c0de305a905cf271ab5fe67cc',
    'bootstrap/helpers/parsers.php' => '8c149f3d35e13da29a687073e39c12a5935eb9a94d22a9547a0f42d49e5a50ed',
    'bootstrap/helpers/docker.php' => 'c0d9e643745aeecc83c1b437c0cf855f2a36fac461d56d424916a964e4168f4b',
];
$vnResult = ['status' => 'refused', 'reason' => 'probe-precondition', 'channelAccepted' => false];
$vnLevel = DB::transactionLevel();
$vnOutputLevel = ob_get_level();
$vnStage = 'source-pin';
ob_start();
try {
    foreach ($vnPins as $vnPath => $vnHash) {
        if (hash_file(base_path($vnPath)) !== $vnHash) {
            throw new RuntimeException('provider-source-mismatch');
        }
    }
    $vnStage = 'input-validation';
    if (($vnRequest['fixtureBaseSha'] ?? '') !== 'f930ef88d4cdb0c4645ea38a67ad080dc7f78c4c'
        || !preg_match('/^[a-f0-9]{40}$/D', $vnRequest['executionSha'] ?? '')
        || !preg_match('/^[a-f0-9]{64}$/D', $vnRequest['overlayDigest'] ?? '')
        || !preg_match('/^[a-f0-9]{64}$/D', $vnRequest['executionReviewDigest'] ?? '')
        || ($vnRequest['acknowledgement'] ?? '') !== 'DISPOSABLE_SYNTHETIC_ONLY'
        || !preg_match('/^[a-zA-Z0-9_-]{1,128}$/D', $vnRequest['application'] ?? '')
        || !preg_match('/^[a-z0-9-]{1,48}$/D', $vnRequest['case'] ?? '')
        || !is_array($vnRequest['compose'] ?? null)) {
        throw new RuntimeException('probe-input-invalid');
    }
    $vnStage = 'fresh-disposable-target';
    $vnApplication = Application::where('uuid', $vnRequest['application'])->sole();
    if (!str_starts_with($vnApplication->name, 'vnprivate')
        || $vnApplication->git_repository !== 'https://github.com/NikitaBabenko/vibenest-compose-contract-fixture'
        || $vnApplication->git_commit_sha !== $vnRequest['executionSha']
        || $vnApplication->build_pack !== 'dockercompose'
        || (int)$vnApplication->compose_parsing_version !== 5
        || ApplicationDeploymentQueue::where('application_id', $vnApplication->id)->exists()
        || $vnApplication->environment_variables()->exists()
        || $vnApplication->environment_variables_preview()->exists()) {
        throw new RuntimeException('fresh-disposable-application-required');
    }
    // Never accept a bearer as input. This value cannot authenticate to any broker/store.
    $vnCanary = hash('sha256', 'VN_SYNTHETIC_NOT_A_CAPABILITY/prehelper-contract/v1');
    $vnKey = 'VN_ARTIFACT_CAPABILITY';
    Bus::fake();
    Queue::fake();
    DB::beginTransaction();
    $vnResult = Model::withoutEvents(function () use ($vnRequest, $vnApplication, $vnCanary, $vnKey, &$vnStage) {
        $vnStage = 'synthetic-row';
        $vnApplication->environment_variables()->create([
            'key' => $vnKey, 'value' => $vnCanary, 'is_preview' => false,
            'is_buildtime' => true, 'is_runtime' => false, 'is_literal' => true,
            'is_multiline' => false, 'is_shown_once' => true,
        ]);
        $vnApplication->unsetRelation('environment_variables');
        $vnApplication->docker_compose_domains = null;
        $vnApplication->docker_compose_raw = Yaml::dump($vnRequest['compose'], 10, 2);
        $vnStage = 'provider-injection-validation';
        validateDockerComposeForInjection($vnApplication->docker_compose_raw);
        // Matches loadComposeFile()->parse() BEFORE the later parse(commit: SHA).
        $vnStage = 'provider-first-parse';
        $vnParsed = convertToArray($vnApplication->parse());
        if (empty($vnParsed['services'])) {
            throw new RuntimeException('parser-returned-no-services');
        }
        $vnYaml = Yaml::dump($vnParsed, 10);
        $vnStored = (string)$vnApplication->fresh()->docker_compose;
        $vnSurfaces = [
            'parser-return' => json_encode($vnParsed, JSON_THROW_ON_ERROR),
            'parser-persisted-compose' => $vnStored,
            // Job 973-984 writes this representation before the build hook.
            'parser-yaml-before-build-hook' => $vnYaml,
        ];
        $vnObservations = [];
        foreach ($vnSurfaces as $vnName => $vnBytes) {
            $vnObservations[$vnName] = [
                'containsSyntheticCapability' => str_contains($vnBytes, $vnCanary),
                'containsReservedName' => str_contains($vnBytes, $vnKey),
                'digest' => hash('sha256', $vnBytes),
                'bytes' => strlen($vnBytes),
            ];
        }
        $vnStage = 'provider-command-transform';
        $vnBuildArgs = generateDockerBuildArgs([
            ['key' => $vnKey, 'value' => $vnCanary, 'is_multiline' => false],
        ])->implode(' ');
        $vnBuild = $vnRequest['buildCommand'];
        $vnAfter = injectDockerComposeBuildArgs(
            injectDockerComposeFlags($vnBuild, '/artifacts/synthetic/private-compose.yaml', '/artifacts/build-time.env'),
            $vnBuildArgs);
        return [
            'status' => 'observed', 'case' => $vnRequest['case'], 'channelAccepted' => false,
            'surfaces' => $vnObservations,
            'commandUnchanged' => $vnAfter === $vnBuild,
            'commandContainsSyntheticCapability' => str_contains($vnAfter, $vnCanary),
            'generatedBuildArgsContainValue' => str_contains($vnBuildArgs, $vnCanary),
            'generatedBuildArgsContainKey' => str_contains($vnBuildArgs, $vnKey),
            'firstExposure' => str_contains($vnStored, $vnCanary)
                ? 'applicationParser-empty-value-db-override-before-custom-build' : null,
            'notExercised' => ['native-remote-write', 'provider-log-redaction', 'compose-cli-interpolation',
                'Dockerfile-ARG-rewrite', 'helper-scrub', 'user-build', 'post-build-runtime-env'],
        ];
    });
} catch (Throwable $vnException) {
    // Neither exception text nor locals may be printed, even with a synthetic canary.
    $vnResult = ['status' => 'refused', 'reason' => 'provider-or-probe-refusal',
        'stage' => $vnStage, 'exceptionClass' => get_class($vnException), 'channelAccepted' => false];
} finally {
    while (DB::transactionLevel() > $vnLevel) {
        DB::rollBack();
    }
    while (ob_get_level() > $vnOutputLevel) {
        ob_end_clean();
    }
}
echo json_encode($vnResult, JSON_THROW_ON_ERROR);
