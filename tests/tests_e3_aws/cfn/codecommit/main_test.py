from e3.aws.cfn.codecommit import Repository


def test_create_repository():
    """RecordSet test."""
    name = "my-repo"
    description = "my repo description"
    r = Repository(name, description)
    assert r.properties["RepositoryName"] == name
    assert r.properties["RepositoryDescription"] == description

    # Resource name should only include alphanum characters
    assert r.name == "myrepo"
