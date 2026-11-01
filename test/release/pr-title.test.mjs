import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePullRequestTitle } from "../../scripts/release/pr-title.mjs";
import { changeLevel } from "../../scripts/release/version-policy.mjs";

test("accepted PR titles have an unambiguous automatic release level", () => {
  for (const [title, level] of [
    ["feat: 支持运行时切换协议栈", "minor"],
    ["fix(windows): repair startup", "patch"],
    ["docs: clarify setup", "patch"],
    ["refactor(config)!: remove an obsolete setting", "major"],
  ]) {
    validatePullRequestTitle(title);
    assert.equal(changeLevel(title, "1.2.3"), level);
  }
  for (const title of [undefined, "", "Add a feature", "feature: new", "feat:", "feat: ", "feat: good\nfix: another", "feat(): empty scope"])
    assert.throws(() => validatePullRequestTitle(title), /Conventional Commit/);
});
