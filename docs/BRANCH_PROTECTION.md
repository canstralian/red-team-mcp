# Setting Up Branch Protection Rules

To ensure code quality checks are enforced before merging, the repository owner should configure branch protection rules.

## GitHub Branch Protection Configuration

### Step 1: Navigate to Settings
1. Go to repository: `https://github.com/canstralian/red-team-mcp`
2. Click **Settings** tab
3. Click **Branches** in the left sidebar

### Step 2: Add Branch Protection Rule
1. Click **Add rule** or **Add branch protection rule**
2. In **Branch name pattern**, enter: `main` (or `master` if that's your default branch)

### Step 3: Configure Required Status Checks
Enable the following options:

#### ✅ Require status checks to pass before merging
- Check this box
- Check: **Require branches to be up to date before merging**
- In the search box, find and select:
  - `Python Code Quality (flake8)` - This is the job name from our workflow

#### ✅ Require a pull request before merging
- Check this box
- Set **Required approvals**: 1 (or more as needed)
- Optional: Check **Dismiss stale pull request approvals when new commits are pushed**

#### ✅ Other Recommended Settings
- **Require conversation resolution before merging** - Ensures all PR comments are addressed
- **Do not allow bypassing the above settings** - Enforces rules even for admins
- **Require linear history** - Keeps git history clean

### Step 4: Save Changes
Click **Create** or **Save changes** at the bottom

## What This Achieves

Once configured, the branch protection rules will:

1. **Block merges** if the `Python Code Quality (flake8)` check fails
2. **Require code review** before merging (if PR approval is enabled)
3. **Ensure quality standards** are maintained across all contributions
4. **Prevent accidental merges** of code with critical errors

## Testing the Protection

To verify it's working:

1. Create a new branch with intentional flake8 errors
2. Open a pull request
3. Wait for the code quality check to run
4. Observe that the merge button is blocked if critical errors are found

## Troubleshooting

### Status check not appearing
- The workflow must run at least once before it appears in the list
- Push a commit to trigger the workflow
- Wait a few minutes and refresh the branch protection settings page

### Can't find the status check
- Verify the workflow file is in `.github/workflows/code-quality.yml`
- Check the job name matches: `Python Code Quality (flake8)`
- Ensure the workflow has run successfully at least once

## Additional Resources

- [GitHub Branch Protection Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Required Status Checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)
